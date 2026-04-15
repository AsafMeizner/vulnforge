import { readFileSync, existsSync, readdirSync } from 'fs';
import path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import {
  getScanFindings,
  updateScanFinding,
  getProjectById,
  type ScanFinding,
} from '../db.js';
import { routeAI } from '../ai/router.js';
import {
  VERIFY_SYSTEM_PROMPT,
  buildVerifyPrompt,
  parseVerifyResponse,
  type VerificationResult,
} from '../ai/prompts/verify.js';
import { blameVulnerableLine } from './git-analyzer.js';
import { scoreExposure } from './attack-surface.js';
import { getChainContext, type VulnChain } from './chain-detector.js';

const execFileAsync = promisify(execFile);

// ── Types ──────────────────────────────────────────────────────────────────

export interface VerificationSummary {
  verified: number;
  rejected: number;
  errors: number;
  total: number;
}

// ── Main Entry Point ───────────────────────────────────────────────────────

/**
 * Run AI verification on all pending findings for a pipeline.
 * Each finding gets its source code read and sent to AI for deep analysis.
 * Verified findings get enriched with AI-written title, description, fix, etc.
 * Rejected findings get auto_rejected with verification reason.
 */
export async function runAIVerification(
  pipelineId: string,
  projectPath: string,
  onProgress?: (completed: number, total: number) => void,
): Promise<VerificationSummary> {
  const findings = getScanFindings({ pipeline_id: pipelineId, status: 'pending' });
  const total = findings.length;
  let verified = 0;
  let rejected = 0;
  let errors = 0;

  // No-AI mode: skip verification, all findings stay as pending for manual review
  try {
    const { getAllAIProviders } = await import('../db.js');
    const providers = getAllAIProviders();
    if (!providers.some(p => p.enabled)) {
      console.log('[AI-Verify] No AI provider enabled — skipping verification (no-AI mode)');
      return { verified: total, rejected: 0, errors: 0, total }; // All pass through for manual review
    }
  } catch { /* proceed with verification attempt */ }

  // Get project name for context
  const firstFinding = findings[0];
  const project = firstFinding?.project_id ? getProjectById(firstFinding.project_id) : null;
  const projectName = project?.name || 'unknown';

  // Process findings sequentially (AI rate limiting)
  // Could parallelize with concurrency limit in the future
  for (let i = 0; i < findings.length; i++) {
    const finding = findings[i];

    try {
      const result = await verifyAndEnrich(finding, projectPath, projectName);

      if (result) {
        if (result.verified) {
          // Enrich the finding with AI-generated metadata
          if (finding.id) {
            updateScanFinding(finding.id, {
              title: result.enriched_title || finding.title,
              description: result.enriched_description || finding.description,
              impact: result.enriched_impact || '',
              suggested_fix: result.enriched_fix || '',
              severity: result.severity || finding.severity,
              cvss: result.cvss_score || finding.cvss,
              cwe: result.cwe || finding.cwe,
              confidence: result.confidence || 'High',
              ai_verification: JSON.stringify(result),
            });
          }
          verified++;
        } else {
          // Reject with AI reasoning
          if (finding.id) {
            updateScanFinding(finding.id, {
              status: 'auto_rejected',
              rejection_reason: result.verification_reason || 'AI verification: not a real vulnerability',
              ai_verification: JSON.stringify(result),
            });
          }
          rejected++;
        }
      } else {
        // AI response unparseable — keep finding as-is (conservative)
        errors++;
      }
    } catch (err: any) {
      console.warn(`[AI-Verify] Error verifying finding ${finding.id}:`, err.message);
      errors++;
      // On error, keep finding as pending (don't auto-reject)
    }

    if (onProgress) onProgress(i + 1, total);

    // Rate limiting delay between verifications
    if (i < findings.length - 1) {
      await new Promise(resolve => setTimeout(resolve, 800));
    }
  }

  return { verified, rejected, errors, total };
}

// ── Single Finding Verification ────────────────────────────────────────────

async function verifyAndEnrich(
  finding: ScanFinding,
  projectPath: string,
  projectName: string,
  chains?: VulnChain[],
  attackSurfaceData?: any,
): Promise<VerificationResult | null> {

  // ── Gather deep context ───────────────────────────────────────────────
  const sourceContext = readSourceContext(finding, projectPath);
  const deepContext = await gatherDeepContext(finding, projectPath);
  const dataFlow = await traceDataFlow(finding, projectPath);
  const blameInfo = await getBlameContext(finding, projectPath);
  const chainContext = chains && finding.id ? getChainContext(finding.id, chains) : [];
  const exposureInfo = attackSurfaceData
    ? scoreExposure(finding.file || '', finding.line_start || 0, attackSurfaceData.entry_points || [], attackSurfaceData.trust_boundaries || [])
    : null;

  // ── Build enhanced prompt ─────────────────────────────────────────────
  let enhancedContext = sourceContext;

  if (deepContext) {
    enhancedContext += '\n\n--- CALLERS (who calls this function) ---\n' + deepContext.callers;
    enhancedContext += '\n\n--- CALLEES (functions called at finding location) ---\n' + deepContext.callees;
  }

  if (dataFlow.reaches_external_input) {
    enhancedContext += `\n\n--- DATA FLOW ---\nExternal input reaches this code via: ${dataFlow.tainted_path.join(' → ')}`;
    enhancedContext += `\nInput sources: ${dataFlow.sources.join(', ')}`;
  } else if (dataFlow.sources.length > 0) {
    enhancedContext += `\n\n--- DATA FLOW ---\nData sources found: ${dataFlow.sources.join(', ')} (external input NOT confirmed)`;
  }

  if (blameInfo) {
    enhancedContext += `\n\n--- GIT BLAME ---\nVulnerable line introduced: ${blameInfo.date} by ${blameInfo.author}`;
    enhancedContext += `\nCommit: ${blameInfo.commit_message} (${blameInfo.age_days} days ago)`;
    if (blameInfo.age_days < 90) enhancedContext += '\nNOTE: This is RECENTLY introduced code (< 90 days)';
  }

  if (chainContext.length > 0) {
    enhancedContext += '\n\n--- VULNERABILITY CHAIN ---\n';
    for (const chain of chainContext) {
      enhancedContext += `CHAIN: ${chain.chain_type} — ${chain.description}\n`;
      enhancedContext += `Combined severity: ${chain.combined_severity}\n`;
      enhancedContext += `Exploitation: ${chain.exploitation_path}\n`;
    }
  }

  if (exposureInfo) {
    enhancedContext += `\n\n--- ATTACK SURFACE ---\nExposure: ${exposureInfo.exposure}`;
    if (exposureInfo.in_pre_auth) enhancedContext += '\nWARNING: This code is in the PRE-AUTH attack surface (reachable before authentication)';
    if (exposureInfo.reachable_from.length > 0) {
      enhancedContext += `\nReachable from: ${exposureInfo.reachable_from.join(', ')}`;
    }
  }

  const userPrompt = buildVerifyPrompt(
    {
      title: finding.title,
      description: finding.description,
      severity: finding.severity,
      cwe: finding.cwe,
      file: finding.file,
      line_start: finding.line_start,
      tool_name: finding.tool_name,
      code_snippet: finding.code_snippet,
    },
    enhancedContext,
    projectName,
  );

  // Call AI
  const response = await routeAI({
    messages: [
      { role: 'system', content: VERIFY_SYSTEM_PROMPT },
      { role: 'user', content: userPrompt },
    ],
    task: 'verify' as any,
    temperature: 0.1,
    maxTokens: 2048,
  });

  if (!response?.content) return null;

  return parseVerifyResponse(response.content);
}

// ── Deep Context Gathering ──────────────────────────────────────────────────

async function gatherDeepContext(
  finding: ScanFinding,
  projectPath: string,
): Promise<{ callers: string; callees: string } | null> {
  if (!finding.file || !finding.line_start) return null;

  const filePath = resolveFilePath(finding.file, projectPath);
  if (!filePath) return null;

  try {
    const content = readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');
    const targetLine = lines[finding.line_start - 1] || '';

    // Extract function name at the finding location
    const funcName = extractFunctionAtLine(lines, finding.line_start - 1);
    if (!funcName) return null;

    // Find callers of this function across the project
    let callers = '';
    try {
      const { stdout } = await execFileAsync('grep', ['-rn', `${funcName}(`, projectPath, '--include=*.c', '--include=*.h', '--include=*.cpp', '--include=*.py', '--include=*.js', '--include=*.ts', '--include=*.go', '-l'], { timeout: 10_000 });
      const callerFiles = stdout.trim().split('\n').filter(Boolean).slice(0, 5);
      for (const cf of callerFiles) {
        if (cf === filePath) continue; // Skip the file itself
        try {
          const { stdout: grepOut } = await execFileAsync('grep', ['-n', `${funcName}(`, cf], { timeout: 5_000 });
          callers += `\n// ${path.relative(projectPath, cf)}:\n${grepOut.trim().slice(0, 500)}\n`;
        } catch { /* ignore */ }
      }
    } catch { /* grep not available or timeout */ }

    // Extract function calls at the finding line
    const callees = extractCallees(lines, finding.line_start - 1, 10);

    return {
      callers: callers || 'No cross-file callers found.',
      callees: callees || 'No callees identified.',
    };
  } catch {
    return null;
  }
}

async function traceDataFlow(
  finding: ScanFinding,
  projectPath: string,
): Promise<{ sources: string[]; tainted_path: string[]; reaches_external_input: boolean }> {
  const sources: string[] = [];
  const taintedPath: string[] = [];
  let reachesExternal = false;

  if (!finding.file || !finding.line_start) {
    return { sources, tainted_path: taintedPath, reaches_external_input: false };
  }

  const filePath = resolveFilePath(finding.file, projectPath);
  if (!filePath) return { sources, tainted_path: taintedPath, reaches_external_input: false };

  try {
    const content = readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

    // Look backward from the finding for external input indicators
    const searchStart = Math.max(0, finding.line_start - 100);
    const searchEnd = finding.line_start;

    const externalPatterns = [
      { pattern: /\bread\s*\(|recv\s*\(|recvfrom\s*\(|fread\s*\(|fgets\s*\(/, source: 'network/file read' },
      { pattern: /\breq\.(body|query|params|headers)|request\.(body|GET|POST)/, source: 'HTTP request input' },
      { pattern: /\bgetenv\s*\(|os\.environ|process\.env/, source: 'environment variable' },
      { pattern: /\bargv\b|sys\.argv|process\.argv/, source: 'command line argument' },
      { pattern: /\bscanf\s*\(|gets\s*\(|getline\s*\(/, source: 'stdin input' },
      { pattern: /\baccept\s*\(|socket\s*\(/, source: 'network socket' },
      { pattern: /\bfs\.readFile|readFileSync|open\s*\(/, source: 'file system' },
    ];

    for (let i = searchStart; i < searchEnd; i++) {
      const line = lines[i];
      for (const { pattern, source } of externalPatterns) {
        if (pattern.test(line)) {
          sources.push(source);
          taintedPath.push(`line ${i + 1}: ${line.trim().slice(0, 80)}`);
          reachesExternal = true;
        }
      }
    }
  } catch { /* ignore */ }

  return { sources: [...new Set(sources)], tainted_path: taintedPath.slice(0, 5), reaches_external_input: reachesExternal };
}

async function getBlameContext(
  finding: ScanFinding,
  projectPath: string,
): Promise<{ date: string; author: string; commit_message: string; age_days: number } | null> {
  if (!finding.file || !finding.line_start) return null;
  try {
    return await blameVulnerableLine(projectPath, finding.file, finding.line_start);
  } catch {
    return null;
  }
}

// ── Source Code Reader ──────────────────────────────────────────────────────

/**
 * Read source code around the finding location.
 * Returns ±50 lines of context with line numbers.
 */
function readSourceContext(finding: ScanFinding, projectPath: string): string {
  if (!finding.file) return 'Source file not specified.';

  // Resolve file path — could be absolute or relative
  let filePath = finding.file;
  if (!path.isAbsolute(filePath)) {
    filePath = path.join(projectPath, filePath);
  }

  if (!existsSync(filePath)) {
    // Try common path variations
    const alternatives = [
      path.join(projectPath, finding.file),
      path.join(projectPath, 'src', finding.file),
    ];
    const found = alternatives.find(p => existsSync(p));
    if (!found) return `Source file not found: ${finding.file}`;
    filePath = found;
  }

  try {
    const content = readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');
    const targetLine = (finding.line_start || 1) - 1; // 0-indexed
    const contextSize = 50;
    const start = Math.max(0, targetLine - contextSize);
    const end = Math.min(lines.length, targetLine + contextSize + 1);

    const contextLines = lines.slice(start, end).map((line, idx) => {
      const lineNum = start + idx + 1;
      const marker = lineNum === (finding.line_start || 0) ? ' >>>' : '    ';
      return `${marker} ${String(lineNum).padStart(5)} | ${line}`;
    });

    return contextLines.join('\n');
  } catch (err: any) {
    return `Error reading source: ${err.message}`;
  }
}

// ── Additional Helpers ──────────────────────────────────────────────────────

function resolveFilePath(file: string, projectPath: string): string | null {
  let filePath = file;
  if (!path.isAbsolute(filePath)) filePath = path.join(projectPath, filePath);
  if (existsSync(filePath)) return filePath;

  const alternatives = [
    path.join(projectPath, file),
    path.join(projectPath, 'src', file),
  ];
  return alternatives.find(p => existsSync(p)) || null;
}

function extractFunctionAtLine(lines: string[], lineIdx: number): string | null {
  for (let i = lineIdx; i >= Math.max(0, lineIdx - 15); i--) {
    const line = lines[i];
    // C/C++: type name(params) {
    const cMatch = line.match(/\b(\w{2,})\s*\([^)]*\)\s*\{?\s*$/);
    if (cMatch && !['if', 'for', 'while', 'switch', 'return'].includes(cMatch[1])) return cMatch[1];
    // Python: def name(
    const pyMatch = line.match(/\bdef\s+(\w+)\s*\(/);
    if (pyMatch) return pyMatch[1];
    // JS/TS: function name( or name = function/arrow
    const jsMatch = line.match(/\bfunction\s+(\w+)/);
    if (jsMatch) return jsMatch[1];
    const arrowMatch = line.match(/(?:const|let)\s+(\w+)\s*=\s*(?:async\s*)?\(/);
    if (arrowMatch) return arrowMatch[1];
    // Go: func Name(
    const goMatch = line.match(/\bfunc\s+(?:\([^)]+\)\s+)?(\w+)\s*\(/);
    if (goMatch) return goMatch[1];
  }
  return null;
}

function extractCallees(lines: string[], lineIdx: number, range: number): string {
  const calls: string[] = [];
  const start = Math.max(0, lineIdx - range);
  const end = Math.min(lines.length, lineIdx + range);

  for (let i = start; i < end; i++) {
    const callMatch = lines[i].match(/\b(\w{2,})\s*\(/g);
    if (callMatch) {
      for (const call of callMatch) {
        const name = call.replace(/\s*\(/, '');
        if (!['if', 'for', 'while', 'switch', 'return', 'sizeof', 'typeof'].includes(name)) {
          calls.push(`line ${i + 1}: ${name}()`);
        }
      }
    }
  }

  return calls.slice(0, 10).join('\n');
}
