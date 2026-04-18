import crypto from 'crypto';
import { EventEmitter } from 'events';
import {
  createPipelineRun,
  updatePipelineRun,
  getPipelineRun,
  getActivePipelineRuns,
  getProjectById,
  updateProject,
  createProject,
  getScanFindings,
  type PipelineRun,
} from '../db.js';
import { broadcastProgress } from '../ws.js';
import {
  validateRepoUrl,
  repoNameFromUrl,
  cloneRepo,
  detectProjectMeta,
  extractDependencies,
  type ProjectMeta,
} from './git.js';
import { selectToolsForProject } from './tool-selector.js';
import { runSmartFilter } from './smart-filter.js';
import { runAIVerification } from './ai-verify.js';
import { analyzeRecentCommits, type GitAnalysis } from './git-analyzer.js';
import { generateAttackSurface, type AttackSurface } from './attack-surface.js';
import { huntCVEVariants, type CVEVariant } from './cve-hunter.js';
import { auditConfigs, type ConfigFinding } from './config-auditor.js';
import { filterUnreachableDeps } from './dep-reachability.js';
import { detectChains, type VulnChain } from './chain-detector.js';

// ── Types ──────────────────────────────────────────────────────────────────

export interface PipelineOptions {
  url?: string;           // Git URL to clone
  path?: string;          // Local directory path
  project_id?: number;    // Existing project ID
  branch?: string;
  depth?: number;
  toolOverrides?: string[];  // Override auto-selected tools
}

type PipelineStage = 'cloning' | 'analyzing' | 'scanning' | 'filtering' | 'verifying' | 'ready';

const STAGES: PipelineStage[] = ['cloning', 'analyzing', 'scanning', 'filtering', 'verifying', 'ready'];

// ── Active Pipeline Tracking ───────────────────────────────────────────────

const activePipelines = new Map<string, { cancel: () => void; pause: () => void }>();

// ── Pipeline Runner ────────────────────────────────────────────────────────

/**
 * Runs the full autonomous pipeline:
 * Clone → Analyze → Scan → Filter → Verify → Ready for Review
 */
export async function runPipeline(opts: PipelineOptions): Promise<string> {
  const pipelineId = `pipe-${crypto.randomBytes(6).toString('hex')}`;
  let cancelled = false;

  // Resolve or create project
  let projectId: number;
  let projectPath: string;

  if (opts.project_id) {
    const existing = getProjectById(opts.project_id);
    if (!existing) throw new Error(`Project ${opts.project_id} not found`);
    projectId = existing.id!;
    projectPath = existing.path || '';
  } else if (opts.url) {
    if (!validateRepoUrl(opts.url)) throw new Error('Invalid git repository URL');
    const name = repoNameFromUrl(opts.url);
    projectId = createProject({ name, repo_url: opts.url, branch: opts.branch || null, language: 'detecting...' } as any);
    projectPath = ''; // Will be set after clone
  } else if (opts.path) {
    const name = opts.path.split(/[/\\]/).pop() || 'local-project';
    projectId = createProject({ name, path: opts.path, language: 'detecting...' } as any);
    projectPath = opts.path;
  } else {
    throw new Error('Must provide url, path, or project_id');
  }

  // Create pipeline run record
  createPipelineRun({
    id: pipelineId,
    project_id: projectId,
    status: 'pending',
    current_stage: '',
    progress: 0,
    scan_job_ids: '[]',
    findings_total: 0,
    findings_after_filter: 0,
    findings_after_verify: 0,
    config: JSON.stringify(opts),
    started_at: new Date().toISOString(),
  });

  // Register cancellation and pause controls
  let paused = false;
  activePipelines.set(pipelineId, {
    cancel: () => { cancelled = true; },
    pause: () => { paused = true; },
  });

  const checkState = (): 'run' | 'paused' | 'cancelled' => {
    if (cancelled) return 'cancelled';
    if (paused) return 'paused';
    return 'run';
  };

  // Run pipeline async
  runPipelineAsync(pipelineId, projectId, projectPath, opts, checkState).catch(err => {
    console.error(`[Pipeline ${pipelineId}] Fatal error:`, err);
    updatePipelineRun(pipelineId, {
      status: 'failed',
      error: err.message,
      completed_at: new Date().toISOString(),
    });
    broadcastProgress('pipeline', pipelineId, {
      step: 'Pipeline failed',
      detail: err.message,
      progress: 0,
      status: 'error',
    });
  }).finally(() => {
    activePipelines.delete(pipelineId);
  });

  return pipelineId;
}

async function runPipelineAsync(
  pipelineId: string,
  projectId: number,
  projectPath: string,
  opts: PipelineOptions,
  checkState: () => 'run' | 'paused' | 'cancelled',
): Promise<void> {

  const emit = (stage: string, detail: string, progress: number, status: 'running' | 'complete' | 'error' = 'running') => {
    broadcastProgress('pipeline', pipelineId, { step: stage, detail, progress, status });
  };

  /** Check if pipeline should stop. Returns true if we should exit. */
  const shouldStop = (): boolean => {
    const state = checkState();
    if (state === 'cancelled') return true;
    if (state === 'paused') {
      updatePipelineRun(pipelineId, { status: 'paused' });
      emit('Paused', 'Pipeline paused - resume from the Hunt page or API', getPipelineRun(pipelineId)?.progress || 0);
      return true;
    }
    return false;
  };

  // ── Stage 1: Clone (if URL provided) ──────────────────────────────────
  if (opts.url && !projectPath) {
    updatePipelineRun(pipelineId, { status: 'cloning', current_stage: 'cloning', progress: 5 });
    emit('Cloning repository', `git clone ${opts.url}`, 5);

    try {
      updateProject(projectId, { clone_status: 'cloning' } as any);
      const result = await cloneRepo(opts.url, { branch: opts.branch, depth: opts.depth || 1 });
      projectPath = result.localPath;

      updateProject(projectId, {
        path: result.localPath,
        branch: result.branch,
        clone_status: 'ready',
        commit_hash: result.commitHash,
      } as any);
      emit('Clone complete', `Cloned to ${result.localPath}`, 15);
    } catch (err: any) {
      updateProject(projectId, { clone_status: 'failed', clone_error: err.message } as any);
      throw new Error(`Clone failed: ${err.message}`);
    }
  }

  if (shouldStop()) return abortPipeline(pipelineId, checkState());
  if (!projectPath) throw new Error('No project path available');

  // ── Stage 2: Analyze ──────────────────────────────────────────────────
  updatePipelineRun(pipelineId, { status: 'scanning', current_stage: 'analyzing', progress: 18 });
  emit('Analyzing project', 'Detecting languages, build systems, and dependencies', 18);

  const meta = detectProjectMeta(projectPath);
  const deps = extractDependencies(projectPath);

  updateProject(projectId, {
    language: meta.primaryLanguage,
    build_system: JSON.stringify(meta.buildSystems),
    dependencies: JSON.stringify(deps),
    languages: JSON.stringify(meta.languages),
  } as any);

  emit('Analysis complete',
    `${meta.languages.join(', ')} | ${meta.buildSystems.join(', ') || 'no build system'} | ${deps.reduce((s, d) => s + d.packages.length, 0)} deps`,
    20);

  if (shouldStop()) return abortPipeline(pipelineId, checkState());

  // ── Stage 2b: Git History Analysis ──────────────────────────────────
  emit('Git analysis', 'Analyzing commit history for security-relevant changes', 21);
  let gitAnalysis: GitAnalysis | null = null;
  try {
    gitAnalysis = await analyzeRecentCommits(projectPath, 200);
    if (gitAnalysis.security_commits.length > 0) {
      emit('Git analysis', `Found ${gitAnalysis.security_commits.length} security-relevant commits, ${gitAnalysis.hot_files.length} hot files`, 22);
    }
  } catch (err: any) {
    emit('Git analysis', `Skipped: ${err.message}`, 22);
  }

  // ── Stage 2c: Attack Surface Mapping ────────────────────────────────
  emit('Attack surface', 'Mapping entry points and trust boundaries', 23);
  let attackSurface: AttackSurface | null = null;
  try {
    attackSurface = generateAttackSurface(projectPath, meta);
    emit('Attack surface',
      `${attackSurface.total_entry_points} entry points: ${Object.entries(attackSurface.exposure_summary).map(([k, v]) => `${v} ${k}`).join(', ')}`,
      24);
  } catch (err: any) {
    emit('Attack surface', `Skipped: ${err.message}`, 24);
  }

  if (shouldStop()) return abortPipeline(pipelineId, checkState());

  // ── Stage 3: Select & Run Tools ───────────────────────────────────────
  const selection = opts.toolOverrides
    ? { tools: opts.toolOverrides, plugins: [], reason: 'Manual tool override' }
    : selectToolsForProject(meta);

  emit('Starting scans',
    `${selection.tools.length} tools + ${selection.plugins.length} plugins selected: ${selection.reason}`,
    25);

  // Import scan queue dynamically to avoid circular deps
  const { scanQueue } = await import('../scanner/queue.js');

  // Enqueue all tools - enqueue(projectId, projectPath, toolNames[], autoTriage)
  const scanJobIds: string[] = [];
  for (const toolName of selection.tools) {
    try {
      const jobs = scanQueue.enqueue(projectId, projectPath, [toolName], false);
      for (const j of jobs) scanJobIds.push(j.id);
    } catch (err: any) {
      console.warn(`[Pipeline] Failed to enqueue tool ${toolName}:`, err.message);
    }
  }

  updatePipelineRun(pipelineId, {
    scan_job_ids: JSON.stringify(scanJobIds),
    current_stage: 'scanning',
    progress: 30,
  });

  // Run plugins in parallel (fire-and-forget style like existing plugin runs)
  for (const pluginConfig of selection.plugins) {
    try {
      const { getIntegration } = await import('../plugins/integrations/index.js');
      const integration = getIntegration(pluginConfig.pluginName);
      if (integration) {
        // Run plugin async, don't block the pipeline
        integration.run(projectPath, pluginConfig.options || {}).then(async (result: any) => {
          if (result && result.findings) {
            const db = await import('../db.js');
            for (const f of result.findings) {
              db.createScanFinding({
                project_id: projectId,
                pipeline_id: pipelineId,
                title: f.title || f.rule_id || 'Plugin finding',
                severity: f.severity || 'Medium',
                file: f.file || '',
                line_start: f.line,
                description: f.message || f.description || '',
                tool_name: pluginConfig.pluginName,
                confidence: 'Medium',
                status: 'pending',
              } as any);
            }
          }
        }).catch(err => {
          console.warn(`[Pipeline] Plugin ${pluginConfig.pluginName} failed:`, err.message);
        });
      }
    } catch (err: any) {
      console.warn(`[Pipeline] Plugin ${pluginConfig.pluginName} not available:`, err.message);
    }
  }

  // Run CVE variant hunting in parallel with scans
  emit('CVE variant hunt', 'Searching for known CVE patterns...', 32);
  try {
    const cveVariants = huntCVEVariants(projectPath, meta);
    if (cveVariants.length > 0) {
      const { createScanFinding } = await import('../db.js');
      for (const v of cveVariants) {
        createScanFinding({
          project_id: projectId,
          pipeline_id: pipelineId,
          title: `[CVE Variant] ${v.cve_name}: ${v.pattern_type} in ${v.file}`,
          severity: v.severity as any,
          cwe: v.cwe,
          file: v.file,
          line_start: v.line,
          description: `${v.evidence}\n\nBased on pattern: ${v.cve_id}`,
          tool_name: 'cve_variant_hunter',
          confidence: v.confidence === 'high' ? 'High' : 'Medium',
          status: 'pending',
          code_snippet: v.match,
        } as any);
      }
      emit('CVE variant hunt', `Found ${cveVariants.length} potential CVE variants`, 34);
    } else {
      emit('CVE variant hunt', 'No CVE variant patterns matched', 34);
    }
  } catch (err: any) {
    emit('CVE variant hunt', `Skipped: ${err.message}`, 34);
  }

  // Run config audit in parallel
  emit('Config audit', 'Scanning configuration files for security issues...', 34);
  try {
    const configFindings = auditConfigs(projectPath);
    if (configFindings.length > 0) {
      const { createScanFinding } = await import('../db.js');
      for (const cf of configFindings) {
        createScanFinding({
          project_id: projectId,
          pipeline_id: pipelineId,
          title: `[Config] ${cf.title}`,
          severity: cf.severity as any,
          file: cf.file,
          line_start: cf.line,
          description: `${cf.description}\n\nFix: ${cf.fix}`,
          tool_name: 'config_auditor',
          confidence: 'High',
          status: 'pending',
          code_snippet: cf.match,
        } as any);
      }
      emit('Config audit', `Found ${configFindings.length} configuration issues`, 35);
    } else {
      emit('Config audit', 'No configuration issues found', 35);
    }
  } catch (err: any) {
    emit('Config audit', `Skipped: ${err.message}`, 35);
  }

  // ── Track F: Supply-chain & backdoor detection ────────────────────────
  emit('Supply-chain scan', 'Looking for malicious deps, secrets-in-history, weak crypto, hidden routes, obfuscation...', 35);
  try {
    const { runSupplyChainScan } = await import('./supply-chain/index.js');
    const scFindings = await runSupplyChainScan(projectPath, meta);
    if (scFindings.length > 0) {
      const { createScanFinding } = await import('../db.js');
      for (const f of scFindings) {
        createScanFinding({
          project_id: projectId,
          pipeline_id: pipelineId,
          title: `[SupplyChain/${f.subcategory}] ${f.title}`,
          severity: f.severity as any,
          cwe: f.cwe,
          file: f.file,
          line_start: f.line_start,
          description: `${f.evidence}${f.remediation ? '\n\nRemediation: ' + f.remediation : ''}`,
          tool_name: 'supply_chain',
          confidence: f.confidence >= 0.8 ? 'High' : f.confidence >= 0.5 ? 'Medium' : 'Low',
          status: 'pending',
        } as any);
      }
      emit('Supply-chain scan', `Found ${scFindings.length} supply-chain issues`, 36);
    } else {
      emit('Supply-chain scan', 'Clean - no supply-chain issues detected', 36);
    }
  } catch (err: any) {
    emit('Supply-chain scan', `Skipped: ${err.message}`, 36);
  }

  // ── Track G + H: Injection + Web/API/IaC detectors ─────────────────────
  emit('Code detectors', 'Running injection + web/API/IaC misconfig detectors...', 36);
  try {
    const { runInjectionDetectors } = await import('./detectors/injection/index.js');
    const { runWebDetectors } = await import('./detectors/web/index.js');
    const langs: string[] = Array.isArray(meta.languages) ? meta.languages : [];
    const deps: string[] = Array.isArray(meta.dependencyFiles) ? meta.dependencyFiles : [];
    const [injFindings, webFindings] = await Promise.all([
      runInjectionDetectors(projectPath, langs, deps).catch(() => []),
      runWebDetectors(projectPath, langs, deps).catch(() => []),
    ]);
    const all = [...injFindings, ...webFindings];
    if (all.length > 0) {
      const { createScanFinding } = await import('../db.js');
      for (const f of injFindings) {
        createScanFinding({
          project_id: projectId,
          pipeline_id: pipelineId,
          title: `[Injection/${f.subcategory}] ${f.title}`,
          severity: f.severity as any,
          cwe: f.cwe,
          file: f.file,
          line_start: f.line_start,
          description: `${f.evidence}`,
          tool_name: 'injection_detectors',
          confidence: f.confidence === 'high' ? 'High' : f.confidence === 'medium' ? 'Medium' : 'Low',
          status: 'pending',
        } as any);
      }
      for (const f of webFindings) {
        createScanFinding({
          project_id: projectId,
          pipeline_id: pipelineId,
          title: `[${f.category}/${f.subcategory}] ${f.title}`,
          severity: f.severity as any,
          cwe: f.cwe,
          file: f.file,
          line_start: f.line_start,
          line_end: f.line_end,
          description: `${f.evidence}`,
          tool_name: 'web_detectors',
          confidence: f.confidence,
          status: 'pending',
        } as any);
      }
      emit('Code detectors', `Found ${injFindings.length} injection + ${webFindings.length} web/IaC findings`, 37);
    } else {
      emit('Code detectors', 'No injection or web/IaC issues found', 37);
    }
  } catch (err: any) {
    emit('Code detectors', `Skipped: ${err.message}`, 37);
  }

  // Wait for all scan jobs to complete
  emit('Running scans', `Waiting for ${scanJobIds.length} tool scans to complete...`, 38);

  await waitForScansComplete(scanQueue, pipelineId, scanJobIds, emit, () => checkState() === 'cancelled');

  if (shouldStop()) return abortPipeline(pipelineId, checkState());

  // Count raw findings
  const rawFindings = getScanFindings({ pipeline_id: pipelineId });
  const rawCount = rawFindings.length;
  updatePipelineRun(pipelineId, { findings_total: rawCount, progress: 52 });
  emit('Scans complete', `${rawCount} raw findings from all tools + CVE hunt + config audit`, 52);

  // ── Stage 4: Smart FP Filtering ───────────────────────────────────────
  updatePipelineRun(pipelineId, { current_stage: 'filtering', progress: 55 });
  emit('Filtering false positives', '5-tier filtering: regex → dedup → AI → dep reachability → chain detection', 55);

  // ── Stage 4-pre: Triage memory (Parasoft-style history-aware auto-triage) ──
  try {
    const { applyTriageMemoryToBatch } = await import('../ai/triage-memory.js');
    const { updateScanFinding } = await import('../db.js');
    const pendingBeforeMemory = getScanFindings({ pipeline_id: pipelineId, status: 'pending' });
    const memResult = applyTriageMemoryToBatch(pendingBeforeMemory);
    // Persist any auto-applied decisions back to the DB
    if (memResult.applied > 0) {
      for (const f of pendingBeforeMemory) {
        if (f.status === 'auto_rejected' && f.id) {
          updateScanFinding(f.id, {
            status: 'auto_rejected',
            rejection_reason: f.rejection_reason,
            ai_filter_reason: f.ai_filter_reason,
          } as any);
        }
      }
    }
    emit(
      'Triage memory',
      `Auto-applied ${memResult.applied} historical decisions, ${memResult.hinted} low-confidence hints`,
      54
    );
  } catch (err: any) {
    emit('Triage memory', `Skipped: ${err.message}`, 54);
  }

  const filterResult = await runSmartFilter(pipelineId, projectPath);

  // ── Stage 4b: Dependency Reachability ─────────────────────────────────
  emit('Dep reachability', 'Checking if vulnerable dependencies are actually called...', 62);
  try {
    const pendingAfterFilter = getScanFindings({ pipeline_id: pipelineId, status: 'pending' });
    const depResult = filterUnreachableDeps(pendingAfterFilter, projectPath);
    if (depResult.rejected.length > 0) {
      const { updateScanFinding } = await import('../db.js');
      for (const r of depResult.rejected) {
        if (r.finding.id) {
          updateScanFinding(r.finding.id, {
            status: 'auto_rejected',
            rejection_reason: r.reason,
            ai_filter_reason: `Dep reachability: ${r.reason}`,
          });
        }
      }
      emit('Dep reachability', `Filtered ${depResult.rejected.length} unreachable dependency findings`, 65);
    }
  } catch (err: any) {
    emit('Dep reachability', `Skipped: ${err.message}`, 65);
  }

  // ── Stage 4c: Vulnerability Chain Detection ───────────────────────────
  emit('Chain detection', 'Looking for exploitable vulnerability chains...', 66);
  let chains: VulnChain[] = [];
  try {
    const pendingForChains = getScanFindings({ pipeline_id: pipelineId, status: 'pending' });
    chains = detectChains(pendingForChains);
    if (chains.length > 0) {
      emit('Chain detection', `Found ${chains.length} vulnerability chains`, 68);
      // Boost severity of chained findings
      const { updateScanFinding } = await import('../db.js');
      for (const chain of chains) {
        for (const fId of chain.finding_ids) {
          updateScanFinding(fId, {
            description: `[CHAIN: ${chain.chain_type}] ${chain.exploitation_path}\n\n` + (getScanFindings({}).find(f => f.id === fId)?.description || ''),
          } as any);
        }
      }
    } else {
      emit('Chain detection', 'No exploitable chains found', 68);
    }
  } catch (err: any) {
    emit('Chain detection', `Skipped: ${err.message}`, 68);
  }

  const afterAllFilters = getScanFindings({ pipeline_id: pipelineId, status: 'pending' }).length;
  updatePipelineRun(pipelineId, {
    findings_after_filter: afterAllFilters,
    progress: 72,
  });
  emit('Filtering complete',
    `${rawCount} → ${afterAllFilters} findings (regex + dedup + AI + dep reachability) | ${chains.length} chains detected`,
    72);

  if (shouldStop()) return abortPipeline(pipelineId, checkState());

  // ── Stage 5: AI Verification & Enrichment (with deep context) ─────────
  const pendingFindings = getScanFindings({ pipeline_id: pipelineId, status: 'pending' });

  if (pendingFindings.length > 0) {
    updatePipelineRun(pipelineId, { current_stage: 'verifying', progress: 75 });
    emit('AI verification',
      `Deep-verifying ${pendingFindings.length} findings (multi-file context, git blame, data flow, ${chains.length} chains)...`, 75);

    const verifyResult = await runAIVerification(pipelineId, projectPath, (completed, total) => {
      const progress = 75 + Math.round((completed / total) * 20);
      emit('AI verification', `Verified ${completed}/${total} findings`, progress);
    });

    updatePipelineRun(pipelineId, {
      findings_after_verify: verifyResult.verified,
      progress: 95,
    });
    emit('Verification complete',
      `${verifyResult.verified} verified, ${verifyResult.rejected} rejected by AI`,
      95);
  } else {
    updatePipelineRun(pipelineId, { findings_after_verify: 0, progress: 95 });
    emit('No findings to verify', 'All findings were filtered out', 95);
  }

  // ── Stage 6: Ready for Review ─────────────────────────────────────────
  const finalCount = getScanFindings({ pipeline_id: pipelineId, status: 'pending' }).length;

  updatePipelineRun(pipelineId, {
    status: 'ready',
    current_stage: 'ready',
    progress: 100,
    findings_after_verify: finalCount,
    completed_at: new Date().toISOString(),
  });

  emit('Pipeline complete',
    `${finalCount} findings ready for review (from ${rawCount} raw findings)`,
    100, 'complete');
}

// ── Helpers ────────────────────────────────────────────────────────────────

function abortPipeline(pipelineId: string, state: 'run' | 'paused' | 'cancelled'): void {
  // Defensive no-op: callers check shouldStop() before hitting abort, but
  // typing-wise checkState() can return 'run' too. Treat 'run' as a bug.
  if (state === 'run') {
    console.warn(`[orchestrator] abortPipeline called with state='run' (pipelineId=${pipelineId}) - skipping`);
    return;
  }
  if (state === 'paused') {
    // Paused - keep status as 'paused', don't set completedAt (it's resumable)
    updatePipelineRun(pipelineId, { status: 'paused' });
    broadcastProgress('pipeline', pipelineId, {
      step: 'Paused',
      detail: 'Pipeline paused. Resume anytime from Hunt page.',
      progress: getPipelineRun(pipelineId)?.progress || 0,
      status: 'running', // Not 'error' - it's still alive
    });
  } else {
    updatePipelineRun(pipelineId, {
      status: 'cancelled',
      error: 'Cancelled by user',
      completed_at: new Date().toISOString(),
    });
    broadcastProgress('pipeline', pipelineId, {
      step: 'Cancelled',
      detail: 'Cancelled by user',
      progress: 0,
      status: 'error',
    });
  }
}

/** Wait for all scan jobs in a pipeline to finish. */
async function waitForScansComplete(
  scanQueue: any,
  pipelineId: string,
  jobIds: string[],
  emit: (stage: string, detail: string, progress: number) => void,
  isCancelled: () => boolean,
): Promise<void> {
  if (jobIds.length === 0) return;

  return new Promise<void>((resolve) => {
    let completed = 0;
    const total = jobIds.length;
    const jobSet = new Set(jobIds);

    const onComplete = (data: any) => {
      if (data.pipelineId === pipelineId || jobSet.has(data.jobId || data.id)) {
        completed++;
        const progress = 35 + Math.round((completed / total) * 20);
        emit('Running scans', `${completed}/${total} tools complete`, progress);

        if (completed >= total) {
          scanQueue.removeListener('job:complete', onComplete);
          scanQueue.removeListener('job:error', onError);
          resolve();
        }
      }
    };

    const onError = (data: any) => {
      if (data.pipelineId === pipelineId || jobSet.has(data.jobId || data.id)) {
        completed++;
        if (completed >= total) {
          scanQueue.removeListener('job:complete', onComplete);
          scanQueue.removeListener('job:error', onError);
          resolve();
        }
      }
    };

    // Also listen for queue:drain as fallback
    const onDrain = () => {
      // Give plugins a moment to finish writing findings
      setTimeout(() => {
        scanQueue.removeListener('job:complete', onComplete);
        scanQueue.removeListener('job:error', onError);
        scanQueue.removeListener('queue:drain', onDrain);
        resolve();
      }, 2000);
    };

    scanQueue.on('job:complete', onComplete);
    scanQueue.on('job:error', onError);
    scanQueue.on('queue:drain', onDrain);

    // Safety timeout: 10 minutes max for all scans
    setTimeout(() => {
      scanQueue.removeListener('job:complete', onComplete);
      scanQueue.removeListener('job:error', onError);
      scanQueue.removeListener('queue:drain', onDrain);
      resolve();
    }, 600_000);
  });
}

/**
 * Cancel a running pipeline.
 *
 * Two code paths:
 *   1. The pipeline is in memory (normal case) - call its cancel closure
 *      which propagates the signal to every running stage.
 *   2. The pipeline is an orphan (DB says it's running, but there's no
 *      in-memory handle - e.g. the server restarted mid-clone). We
 *      heal the zombie by flipping the DB row to status='cancelled'
 *      directly so the UI can stop polling it forever.
 *
 * Returns true in either case; false only when the row doesn't exist
 * or is already in a terminal state.
 */
export function cancelPipeline(pipelineId: string): boolean {
  const active = activePipelines.get(pipelineId);
  if (active) {
    active.cancel();
    return true;
  }
  // Orphan path: no worker, but maybe a stale DB row.
  const row = getPipelineRun(pipelineId);
  if (!row) return false;
  const terminal = ['ready', 'completed', 'failed', 'cancelled'];
  if (terminal.includes(row.status)) return false;
  updatePipelineRun(pipelineId, {
    status: 'cancelled',
    current_stage: 'cancelled',
    error: 'Cancelled (orphan recovery - no live worker)',
    completed_at: new Date().toISOString(),
  });
  return true;
}

/**
 * Boot-time reconciliation: any pipeline in a non-terminal status when
 * the process starts up can't possibly still be running (we just booted).
 * Flip them to failed so the UI doesn't show fake "in-progress" rows
 * and so users can start a fresh pipeline on the same project.
 *
 * Called once from server startup. Safe to call multiple times.
 */
export function reconcileOrphanPipelines(): { reaped: number } {
  const active = getActivePipelineRuns();
  let reaped = 0;
  for (const row of active) {
    if (activePipelines.has(row.id)) continue; // really running (rare - same process)
    updatePipelineRun(row.id, {
      status: 'failed',
      error: 'Orphaned at server startup (worker died)',
      completed_at: new Date().toISOString(),
    });
    reaped++;
  }
  if (reaped > 0) console.log(`[pipeline] reconcileOrphanPipelines reaped ${reaped}`);
  return { reaped };
}

/** Pause a running pipeline - preserves progress for later resume. */
export function pausePipeline(pipelineId: string): boolean {
  const active = activePipelines.get(pipelineId);
  if (active) {
    active.pause();
    return true;
  }
  return false;
}

/**
 * Resume a paused pipeline. Re-enters the pipeline at the stage it was paused.
 * Stages already completed (clone, scan results in DB) are skipped.
 */
export async function resumePipeline(pipelineId: string): Promise<boolean> {
  const pipeline = getPipelineRun(pipelineId);
  if (!pipeline || pipeline.status !== 'paused') return false;

  const project = getProjectById(pipeline.project_id);
  if (!project?.path) return false;

  const opts: PipelineOptions = JSON.parse(pipeline.config || '{}');

  // Mark as running again
  updatePipelineRun(pipelineId, { status: 'scanning', error: undefined as any });

  // Re-register controls
  let cancelled = false;
  let paused = false;
  activePipelines.set(pipelineId, {
    cancel: () => { cancelled = true; },
    pause: () => { paused = true; },
  });

  const checkState = (): 'run' | 'paused' | 'cancelled' => {
    if (cancelled) return 'cancelled';
    if (paused) return 'paused';
    return 'run';
  };

  // Determine which stage to resume from
  const stage = pipeline.current_stage || 'scanning';
  const progress = pipeline.progress || 0;

  broadcastProgress('pipeline', pipelineId, {
    step: 'Resuming',
    detail: `Resuming from "${stage}" stage (${progress}% complete)`,
    progress,
    status: 'running',
  });

  // Run the remainder async
  resumePipelineAsync(pipelineId, pipeline.project_id, project.path, opts, stage, checkState).catch(err => {
    console.error(`[Pipeline ${pipelineId}] Resume error:`, err);
    updatePipelineRun(pipelineId, {
      status: 'failed',
      error: err.message,
      completed_at: new Date().toISOString(),
    });
  }).finally(() => {
    activePipelines.delete(pipelineId);
  });

  return true;
}

/**
 * Internal: run pipeline stages starting from the resume point.
 * Skips stages that already completed based on DB state.
 */
async function resumePipelineAsync(
  pipelineId: string,
  projectId: number,
  projectPath: string,
  opts: PipelineOptions,
  resumeStage: string,
  checkState: () => 'run' | 'paused' | 'cancelled',
): Promise<void> {
  const emit = (stage: string, detail: string, progress: number, status: 'running' | 'complete' | 'error' = 'running') => {
    broadcastProgress('pipeline', pipelineId, { step: stage, detail, progress, status });
  };

  const shouldStop = (): boolean => {
    const state = checkState();
    if (state === 'cancelled') return true;
    if (state === 'paused') {
      updatePipelineRun(pipelineId, { status: 'paused' });
      emit('Paused', 'Pipeline paused again', getPipelineRun(pipelineId)?.progress || 0);
      return true;
    }
    return false;
  };

  // Stage ordering: which stages come after the resume point?
  const stageOrder = ['cloning', 'analyzing', 'scanning', 'filtering', 'verifying', 'ready'];
  const resumeIdx = stageOrder.indexOf(resumeStage);

  // Skip to the right stage. Findings from previous scans are already in DB.
  const meta = detectProjectMeta(projectPath);

  if (resumeIdx <= stageOrder.indexOf('filtering')) {
    // Need to re-run filtering on existing findings
    emit('Resuming filter', 'Re-running false positive filtering on existing findings...', 55);
    updatePipelineRun(pipelineId, { current_stage: 'filtering', progress: 55 });

    const { runSmartFilter } = await import('./smart-filter.js');
    await runSmartFilter(pipelineId, projectPath);

    // Dep reachability
    try {
      const pendingAfterFilter = getScanFindings({ pipeline_id: pipelineId, status: 'pending' });
      const { filterUnreachableDeps } = await import('./dep-reachability.js');
      const { updateScanFinding } = await import('../db.js');
      const depResult = filterUnreachableDeps(pendingAfterFilter, projectPath);
      if (depResult.rejected.length > 0) {
        for (const r of depResult.rejected) {
          if (r.finding.id) {
            updateScanFinding(r.finding.id, {
              status: 'auto_rejected',
              rejection_reason: r.reason,
            });
          }
        }
      }
    } catch { /* skip */ }

    // Chain detection
    try {
      const pendingForChains = getScanFindings({ pipeline_id: pipelineId, status: 'pending' });
      const { detectChains } = await import('./chain-detector.js');
      detectChains(pendingForChains);
    } catch { /* skip */ }

    if (shouldStop()) return abortPipeline(pipelineId, checkState());
  }

  if (resumeIdx <= stageOrder.indexOf('verifying')) {
    // Run AI verification on remaining pending findings
    const pendingFindings = getScanFindings({ pipeline_id: pipelineId, status: 'pending' });

    if (pendingFindings.length > 0) {
      updatePipelineRun(pipelineId, { current_stage: 'verifying', progress: 75 });
      emit('AI verification', `Verifying ${pendingFindings.length} findings...`, 75);

      const { runAIVerification } = await import('./ai-verify.js');
      const verifyResult = await runAIVerification(pipelineId, projectPath, (completed, total) => {
        const progress = 75 + Math.round((completed / total) * 20);
        emit('AI verification', `Verified ${completed}/${total}`, progress);
      });

      updatePipelineRun(pipelineId, { findings_after_verify: verifyResult.verified, progress: 95 });
    }

    if (shouldStop()) return abortPipeline(pipelineId, checkState());
  }

  // Mark complete
  const finalCount = getScanFindings({ pipeline_id: pipelineId, status: 'pending' }).length;
  updatePipelineRun(pipelineId, {
    status: 'ready',
    current_stage: 'ready',
    progress: 100,
    findings_after_verify: finalCount,
    completed_at: new Date().toISOString(),
  });

  emit('Pipeline complete', `${finalCount} findings ready for review (resumed)`, 100, 'complete');
}
