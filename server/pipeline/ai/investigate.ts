/**
 * Investigate Mode — interactive AI investigation loop with per-step approval.
 * State lives in SQLite session_state so the frontend can poll progress.
 */
import crypto from 'crypto';
import cp from 'child_process';
import { promisify } from 'util';
import {
  setSessionState,
  getSessionState,
  getVulnerabilityById,
} from '../../db.js';
import { routeAI } from '../../ai/router.js';

const runCmd = promisify(cp.execFile);

export type InvestigateStepStatus = 'pending' | 'approved' | 'rejected' | 'executed' | 'failed';

export interface InvestigateStep {
  index: number;
  thought: string;
  proposed_action: string;
  proposed_args?: Record<string, any>;
  status: InvestigateStepStatus;
  result?: string;
  approved_at?: string;
  executed_at?: string;
}

export interface InvestigateSession {
  id: string;
  finding_id?: number;
  goal: string;
  status: 'active' | 'completed' | 'cancelled';
  steps: InvestigateStep[];
  context: Record<string, any>;
  created_at: string;
  updated_at: string;
}

const SYSTEM_PROMPT = `You are an elite vulnerability researcher walking through an investigation one step at a time.

For EACH step, propose ONE concrete action the user should approve before you proceed. Each step should be small, focused, and verifiable.

Available action types:
- "read_file"        {file, line_start?, line_end?}
- "find_definition"  {function}
- "find_callers"     {function}
- "run_tool"         {type, tool, config}
- "git_blame"        {file, line}
- "analyze_commit"   {sha}
- "list_hypotheses"
- "create_note"      {title, content, type}
- "done"

Return ONLY a JSON object:
{
  "thought": "your reasoning",
  "action": "action_name",
  "args": { ... }
}

Be precise. Be concise. Each action builds on the previous result.`;

export async function startInvestigation(goal: string, findingId?: number): Promise<InvestigateSession> {
  const id = `inv-${crypto.randomBytes(4).toString('hex')}`;
  const now = new Date().toISOString();

  const context: Record<string, any> = { goal };
  if (findingId) {
    const vuln = getVulnerabilityById(findingId);
    if (vuln) {
      context.finding = {
        id: vuln.id,
        title: vuln.title,
        severity: vuln.severity,
        file: vuln.file,
        line_start: vuln.line_start,
        description: vuln.description,
        cwe: vuln.cwe,
        project_id: vuln.project_id,
      };
    }
  }

  const session: InvestigateSession = {
    id,
    finding_id: findingId,
    goal,
    status: 'active',
    steps: [],
    context,
    created_at: now,
    updated_at: now,
  };

  saveSession(session);
  return session;
}

export async function proposeNextStep(sessionId: string): Promise<InvestigateStep> {
  const session = loadSession(sessionId);
  if (!session) throw new Error(`Investigation ${sessionId} not found`);
  if (session.status !== 'active') throw new Error(`Investigation ${sessionId} is ${session.status}`);

  const parts: string[] = [`Goal: ${session.goal}`, ''];
  if (session.context.finding) {
    parts.push(`## Finding context\n${JSON.stringify(session.context.finding, null, 2)}`);
    parts.push('');
  }
  parts.push('## Steps so far');
  if (session.steps.length === 0) {
    parts.push('(none)');
  } else {
    parts.push(session.steps.map((s, i) =>
      `Step ${i + 1}: ${s.thought}\n  Action: ${s.proposed_action} ${JSON.stringify(s.proposed_args || {})}\n  Result: ${s.result || '(pending)'}`
    ).join('\n\n'));
  }
  parts.push('');
  parts.push('What is the NEXT single step? Respond with JSON only.');

  const response = await routeAI({
    messages: [{ role: 'user', content: parts.join('\n') }],
    systemPrompt: SYSTEM_PROMPT,
    temperature: 0.2,
    maxTokens: 1024,
    task: 'deep-analyze' as any,
  });

  let parsed: { thought: string; action: string; args?: Record<string, any> };
  try {
    let jsonText = response.content.trim();
    const fenceMatch = jsonText.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (fenceMatch) jsonText = fenceMatch[1].trim();
    const objMatch = jsonText.match(/\{[\s\S]*\}/);
    if (objMatch) jsonText = objMatch[0];
    parsed = JSON.parse(jsonText);
  } catch (err: any) {
    throw new Error(`Failed to parse AI response: ${err.message}`);
  }

  const step: InvestigateStep = {
    index: session.steps.length,
    thought: parsed.thought || '(no thought)',
    proposed_action: parsed.action || 'done',
    proposed_args: parsed.args,
    status: 'pending',
  };

  session.steps.push(step);
  session.updated_at = new Date().toISOString();
  saveSession(session);

  return step;
}

export async function executeStep(sessionId: string, stepIndex: number): Promise<InvestigateStep> {
  const session = loadSession(sessionId);
  if (!session) throw new Error(`Investigation ${sessionId} not found`);

  const step = session.steps[stepIndex];
  if (!step) throw new Error(`Step ${stepIndex} not found`);
  if (step.status !== 'pending') throw new Error(`Step ${stepIndex} is ${step.status}`);

  step.status = 'approved';
  step.approved_at = new Date().toISOString();

  try {
    const result = await dispatchAction(step.proposed_action, step.proposed_args || {}, session);
    step.result = result;
    step.status = 'executed';
    step.executed_at = new Date().toISOString();

    if (step.proposed_action === 'done') {
      session.status = 'completed';
    }
  } catch (err: any) {
    step.result = `Error: ${err.message}`;
    step.status = 'failed';
  }

  session.updated_at = new Date().toISOString();
  saveSession(session);
  return step;
}

export function rejectStep(sessionId: string, stepIndex: number, reason?: string): InvestigateStep {
  const session = loadSession(sessionId);
  if (!session) throw new Error(`Investigation ${sessionId} not found`);

  const step = session.steps[stepIndex];
  if (!step) throw new Error(`Step ${stepIndex} not found`);

  step.status = 'rejected';
  step.result = reason ? `Rejected: ${reason}` : 'Rejected by user';
  session.updated_at = new Date().toISOString();
  saveSession(session);
  return step;
}

export function cancelInvestigation(sessionId: string): void {
  const session = loadSession(sessionId);
  if (!session) return;
  session.status = 'cancelled';
  session.updated_at = new Date().toISOString();
  saveSession(session);
}

async function resolveProjectPath(session: InvestigateSession): Promise<string> {
  if (!session.context.finding?.id) return '';
  const { getProjectById } = await import('../../db.js');
  const vuln = getVulnerabilityById(session.context.finding.id);
  if (!vuln?.project_id) return '';
  const p = getProjectById(vuln.project_id);
  return p?.path || '';
}

async function dispatchAction(action: string, args: Record<string, any>, session: InvestigateSession): Promise<string> {
  switch (action) {
    case 'read_file': {
      if (!args.file) return 'Error: file arg required';
      const { readFileSync, existsSync } = await import('fs');
      const path = await import('path');
      const basePath = await resolveProjectPath(session);
      const fullPath = path.isAbsolute(args.file) ? args.file : path.join(basePath, args.file);
      if (!existsSync(fullPath)) return `File not found: ${fullPath}`;
      const content = readFileSync(fullPath, 'utf-8');
      const lines = content.split('\n');
      const start = Math.max(0, (args.line_start || 1) - 1);
      const end = args.line_end ? Math.min(lines.length, args.line_end) : Math.min(lines.length, start + 100);
      return lines.slice(start, end).map((l, i) => `${String(start + i + 1).padStart(5)} | ${l}`).join('\n');
    }

    case 'find_definition':
    case 'find_callers': {
      if (!args.function) return 'Error: function arg required';
      const projectPath = await resolveProjectPath(session);
      if (!projectPath) return 'Error: no project path available';
      try {
        const res = await runCmd('grep', [
          '-rn', '--include=*.c', '--include=*.h', '--include=*.cpp',
          '--include=*.py', '--include=*.js', '--include=*.ts', '--include=*.go',
          '-m', '20', `${args.function}(`, projectPath,
        ], { timeout: 15000, maxBuffer: 4 * 1024 * 1024 });
        const lines = res.stdout.split('\n').filter(Boolean).slice(0, 20);
        return lines.length > 0 ? lines.join('\n') : `No matches for ${args.function}`;
      } catch (err: any) {
        return err.code === 1 ? 'No matches' : `Error: ${err.message}`;
      }
    }

    case 'git_blame': {
      if (!args.file || !args.line) return 'Error: file and line required';
      const { blameVulnerableLine } = await import('../git-analyzer.js');
      const projectPath = await resolveProjectPath(session);
      if (!projectPath) return 'Error: no project path';
      const result = await blameVulnerableLine(projectPath, args.file, Number(args.line));
      if (!result) return 'Blame unavailable';
      return `Line ${result.line}: ${result.author} on ${result.date} (${result.age_days}d ago)\nCommit ${result.commit_hash}: ${result.commit_message}`;
    }

    case 'analyze_commit': {
      if (!args.sha) return 'Error: sha required';
      const { analyzeCommit } = await import('../history/patch-analyzer.js');
      const projectPath = await resolveProjectPath(session);
      if (!projectPath) return 'Error: no project path';
      const result = await analyzeCommit(projectPath, args.sha);
      return `Category: ${result.likely_category}\nFiles: ${result.files_changed.join(', ')}\n+${result.lines_added}/-${result.lines_removed}\nIndicators: ${result.security_indicators.join(', ') || 'none'}`;
    }

    case 'list_hypotheses': {
      const { getNotes } = await import('../../db.js');
      const notes = getNotes({ type: 'hypothesis', limit: 20 });
      return notes.length === 0
        ? 'No hypotheses yet'
        : notes.map(n => `#${n.id} [${n.status}] ${n.title}`).join('\n');
    }

    case 'create_note': {
      if (!args.title || !args.content) return 'Error: title and content required';
      const { getDefaultProvider } = await import('../notes/index.js');
      const { createNote } = await import('../../db.js');
      const provider = await getDefaultProvider();
      const meta = {
        title: args.title,
        type: args.type || 'observation',
        projectId: session.context.finding?.project_id,
        findingIds: session.finding_id ? [session.finding_id] : [],
      };
      const created = await provider.createNote(meta, args.content);
      const noteId = createNote({
        provider: provider.name,
        external_id: created.externalId,
        title: args.title,
        type: args.type || 'observation',
        project_id: session.context.finding?.project_id,
        finding_ids: session.finding_id ? JSON.stringify([session.finding_id]) : '[]',
      });
      return `Created note #${noteId}: ${args.title}`;
    }

    case 'run_tool': {
      if (!args.tool || !args.config) return 'Error: tool and config required';
      const { runtimeJobRunner } = await import('../runtime/job-runner.js');
      const id = await runtimeJobRunner.start({
        type: args.type || 'fuzz',
        tool: args.tool,
        config: args.config,
        findingId: session.finding_id,
      });
      return `Started runtime job ${id}`;
    }

    case 'done':
      return 'Investigation complete';

    default:
      return `Unknown action: ${action}`;
  }
}

function saveSession(session: InvestigateSession): void {
  setSessionState('global', null, `investigation:${session.id}`, JSON.stringify(session));
}

function loadSession(sessionId: string): InvestigateSession | null {
  const rows = getSessionState('global', null, `investigation:${sessionId}`);
  if (rows.length === 0) return null;
  try { return JSON.parse(rows[0].value); } catch { return null; }
}

export function listInvestigations(): InvestigateSession[] {
  const rows = getSessionState('global', null);
  const sessions: InvestigateSession[] = [];
  for (const r of rows) {
    if (r.key.startsWith('investigation:')) {
      try { sessions.push(JSON.parse(r.value)); } catch { /* skip */ }
    }
  }
  return sessions.sort((a, b) => b.updated_at.localeCompare(a.updated_at));
}

export function getInvestigation(id: string): InvestigateSession | null {
  return loadSession(id);
}
