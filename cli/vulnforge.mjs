#!/usr/bin/env node
/**
 * VulnForge CLI.
 *
 * Single-file, zero-deps wrapper around the REST API. Designed to
 * stay readable: ANSI colors by hand, tables by padStart/padEnd, an
 * interactive chat REPL via Node's built-in readline.
 *
 * Usage:
 *   vulnforge status
 *   vulnforge findings [--severity=High] [--status=New] [--limit=20] [--search=xyz]
 *   vulnforge finding <id>
 *   vulnforge hunt <url-or-path> [--branch=main]
 *   vulnforge triage <id>
 *   vulnforge deep-triage <id>
 *   vulnforge investigate list
 *   vulnforge investigate new "<goal>" [--finding=N]
 *   vulnforge chat [--finding=N]
 *   vulnforge config set <key> <value>     # api_base, token
 *   vulnforge config show
 *
 * Config lives at ~/.vulnforge/cli.json and is also overridable via
 * env vars VULNFORGE_API_BASE and VULNFORGE_TOKEN.
 */
import { createInterface } from 'node:readline';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';
import { spawnSync } from 'node:child_process';
import process from 'node:process';
import {
  buildOpenclawMcpEntry,
  openclawAvailable,
  discoverVulnforgeOrigin,
  pingVulnforgeBackend,
  isLoopbackUrl,
} from './openclaw.mjs';

// ── Tiny ANSI colour helpers (no chalk dep) ───────────────────────────────
const ANSI = process.stdout.isTTY ? {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  blue: '\x1b[34m', magenta: '\x1b[35m', cyan: '\x1b[36m', gray: '\x1b[90m',
} : new Proxy({}, { get: () => '' });
const c = (code, s) => `${code}${s}${ANSI.reset}`;
const red = (s) => c(ANSI.red, s);
const green = (s) => c(ANSI.green, s);
const yellow = (s) => c(ANSI.yellow, s);
const blue = (s) => c(ANSI.blue, s);
const cyan = (s) => c(ANSI.cyan, s);
const gray = (s) => c(ANSI.gray, s);
const bold = (s) => c(ANSI.bold, s);

function severityColour(sev) {
  switch ((sev || '').toLowerCase()) {
    case 'critical': return red(sev.toUpperCase().padEnd(8));
    case 'high':     return red(sev.toUpperCase().padEnd(8));
    case 'medium':   return yellow(sev.toUpperCase().padEnd(8));
    case 'low':      return blue(sev.toUpperCase().padEnd(8));
    default:         return gray((sev || '-').padEnd(8));
  }
}

// ── Config + API ──────────────────────────────────────────────────────────
const CONFIG_DIR = join(homedir(), '.vulnforge');
const CONFIG_FILE = join(CONFIG_DIR, 'cli.json');

function loadConfig() {
  const defaults = { api_base: 'http://localhost:3001/api', token: '' };
  try {
    if (existsSync(CONFIG_FILE)) {
      const parsed = JSON.parse(readFileSync(CONFIG_FILE, 'utf8'));
      return { ...defaults, ...parsed };
    }
  } catch { /* ignore */ }
  return defaults;
}

function saveConfig(next) {
  mkdirSync(dirname(CONFIG_FILE), { recursive: true });
  writeFileSync(CONFIG_FILE, JSON.stringify(next, null, 2) + '\n', 'utf8');
}

// Env vars win over file (operator overrides), file wins over defaults.
function resolveConfig() {
  const file = loadConfig();
  return {
    api_base: process.env.VULNFORGE_API_BASE || file.api_base,
    token: process.env.VULNFORGE_TOKEN || file.token,
  };
}

async function api(path, { method = 'GET', body, timeout = 30000 } = {}) {
  const cfg = resolveConfig();
  const url = cfg.api_base.replace(/\/$/, '') + path;
  const headers = { 'content-type': 'application/json' };
  if (cfg.token) headers.authorization = `Bearer ${cfg.token}`;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(url, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
    });
    const text = await res.text();
    if (!res.ok) {
      const short = text.slice(0, 300);
      throw new Error(`HTTP ${res.status} ${res.statusText}: ${short}`);
    }
    if (!text) return null;
    try { return JSON.parse(text); } catch { return text; }
  } finally {
    clearTimeout(t);
  }
}

// ── argv parsing (small, just enough) ────────────────────────────────────
// Parses: `cmd sub arg1 --key=value --flag value positional`
function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq > 0) flags[a.slice(2, eq)] = a.slice(eq + 1);
      else if (argv[i + 1] && !argv[i + 1].startsWith('--')) { flags[a.slice(2)] = argv[++i]; }
      else flags[a.slice(2)] = true;
    } else positional.push(a);
  }
  return { positional, flags };
}

// ── Commands ──────────────────────────────────────────────────────────────

async function cmdStatus() {
  const cfg = resolveConfig();
  console.log(bold('VulnForge status'));
  console.log(gray(`api: ${cfg.api_base}${cfg.token ? '  (authenticated)' : '  (no token)'}`));
  try {
    const health = await api('/health', { timeout: 5000 });
    console.log(`health: ${green('ok')} (uptime ${Math.round(health.uptime)}s)`);
  } catch (err) {
    console.log(`health: ${red('down')} (${err.message})`);
    return 1;
  }
  const counts = await api('/vulnerabilities?limit=1').catch(() => null);
  if (counts) console.log(`findings: ${bold(counts.total)}`);
  const pending = await api('/scan-findings?limit=1&status=pending').catch(() => null);
  if (pending) console.log(`scan queue: ${bold(pending.total)} pending`);
  const active = await api('/pipeline?active=true').catch(() => ({ data: [] }));
  if (active.data && active.data.length > 0) {
    console.log(`${bold('active pipelines:')}`);
    for (const p of active.data) {
      console.log(`  ${gray(p.id)}  ${p.status}  stage=${p.current_stage}  progress=${p.progress}%`);
    }
  } else {
    console.log('active pipelines: none');
  }
}

async function cmdFindings(args) {
  const sp = new URLSearchParams();
  if (args.flags.severity) sp.set('severity', args.flags.severity);
  if (args.flags.status) sp.set('status', args.flags.status);
  if (args.flags.search) sp.set('search', args.flags.search);
  sp.set('limit', args.flags.limit || '20');
  const res = await api(`/vulnerabilities?${sp.toString()}`);
  console.log(bold(`${res.total} finding${res.total === 1 ? '' : 's'} (showing ${res.data.length})`));
  console.log(gray('─'.repeat(80)));
  console.log(`${bold('ID'.padEnd(6))}${bold('SEVERITY')}${bold('  STATUS'.padEnd(14))}${bold('  TITLE')}`);
  for (const v of res.data) {
    const id = String(v.id).padEnd(6);
    const sev = severityColour(v.severity);
    const status = gray((v.status || '-').padEnd(12));
    const title = (v.title || '(no title)').slice(0, 60);
    console.log(`${id}${sev}  ${status}  ${title}`);
  }
}

async function cmdFinding(id) {
  const v = await api(`/vulnerabilities/${id}`);
  console.log(bold(v.title || '(no title)'));
  console.log(`${severityColour(v.severity).trim()}  cvss=${v.cvss ?? '-'}  cwe=${v.cwe ?? '-'}  status=${v.status}`);
  if (v.file) console.log(gray(`${v.file}${v.line_start ? `:${v.line_start}` : ''}`));
  console.log();
  if (v.description) { console.log(bold('Description')); console.log(v.description); console.log(); }
  if (v.impact) { console.log(bold('Impact')); console.log(v.impact); console.log(); }
  if (v.code_snippet) { console.log(bold('Code')); console.log(gray(v.code_snippet)); console.log(); }
  if (v.reproduction_steps) { console.log(bold('Repro')); console.log(v.reproduction_steps); console.log(); }
  if (v.suggested_fix) { console.log(bold('Suggested fix')); console.log(v.suggested_fix); console.log(); }
  if (v.manual_triage) { console.log(bold('Manual triage')); console.log(v.manual_triage); console.log(); }
  if (v.ai_triage) { console.log(bold('AI triage')); console.log(v.ai_triage); console.log(); }
}

async function cmdHunt(targetArg, args) {
  const isUrl = /^https?:\/\//i.test(targetArg) || targetArg.startsWith('git@');
  const body = isUrl
    ? { url: targetArg, branch: args.flags.branch }
    : { path: targetArg };
  console.log(bold(`Starting pipeline on ${targetArg}...`));
  const { pipelineId } = await api('/pipeline/start', { method: 'POST', body });
  console.log(green(`pipelineId: ${pipelineId}`));
  // Poll progress every 2s until terminal. Readable line-at-a-time
  // progress instead of a fake spinner.
  let lastStage = '';
  let lastProgress = -1;
  for (let i = 0; i < 300; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    const p = await api(`/pipeline/${pipelineId}`).catch(() => null);
    if (!p) continue;
    if (p.current_stage !== lastStage || p.progress !== lastProgress) {
      const stage = (p.current_stage || '').slice(0, 80);
      console.log(`  ${gray(`[${String(i * 2).padStart(3)}s]`)}  ${p.status.padEnd(10)}  ${p.progress.toString().padStart(3)}%  ${stage}`);
      lastStage = p.current_stage;
      lastProgress = p.progress;
    }
    if (['completed', 'ready', 'failed', 'cancelled'].includes(p.status)) {
      const verb = p.status === 'failed' ? red('failed') : green(p.status);
      console.log();
      console.log(bold(`pipeline ${verb}`));
      if (p.findings_total) console.log(`  total findings:  ${p.findings_total}`);
      if (p.findings_after_filter) console.log(`  after filter:    ${p.findings_after_filter}`);
      if (p.findings_after_verify) console.log(`  after verify:    ${p.findings_after_verify}`);
      if (p.error) console.log(red(`  error: ${p.error}`));
      return p.status === 'failed' ? 1 : 0;
    }
  }
  console.log(yellow('Timed out polling. Run `vulnforge status` to check progress.'));
  return 1;
}

async function cmdTriage(id, { deep = false } = {}) {
  console.log(bold(`${deep ? 'Deep triaging' : 'Triaging'} finding ${id}...`));
  if (deep) {
    const res = await api(`/scan-findings/${id}/deep-triage`, { method: 'POST', timeout: 300000 });
    const r = res.result || res;
    console.log();
    console.log(`verdict:    ${bold(r.verdict || '?')}`);
    console.log(`confidence: ${r.confidence ?? '?'}%`);
    console.log();
    if (r.rationale) { console.log(bold('Rationale')); console.log(r.rationale); }
  } else {
    await api(`/ai/triage/${id}`, { method: 'POST' });
    console.log(gray('Triage started asynchronously. Re-fetch the finding in ~30s to see ai_triage content.'));
    console.log(`  ${cyan(`vulnforge finding ${id}`)}`);
  }
}

async function cmdInvestigate(sub, args) {
  if (!sub || sub === 'list') {
    const res = await api('/ai-investigate/sessions');
    console.log(bold(`${res.data.length} investigation session${res.data.length === 1 ? '' : 's'}`));
    for (const s of res.data) {
      console.log(`  ${gray(s.id)}  ${s.status.padEnd(12)}  ${s.goal.slice(0, 60)}`);
    }
    return;
  }
  if (sub === 'new') {
    const goal = args.positional[1];
    if (!goal) { console.error('usage: vulnforge investigate new "<goal>"'); return 1; }
    const s = await api('/ai-investigate/sessions', {
      method: 'POST',
      body: { goal, finding_id: args.flags.finding ? Number(args.flags.finding) : undefined },
    });
    console.log(green(`session ${s.id} created`));
    console.log(gray(`  run: vulnforge investigate step ${s.id}`));
    return;
  }
  if (sub === 'step') {
    const id = args.positional[1];
    if (!id) { console.error('usage: vulnforge investigate step <id>'); return 1; }
    const step = await api(`/ai-investigate/sessions/${id}/next-step`, { method: 'POST', timeout: 180000 });
    console.log(bold(`Step ${step.index}`));
    console.log(`  thought: ${step.thought}`);
    console.log(`  action:  ${step.proposed_action}`);
    if (step.proposed_args) console.log(`  args:    ${JSON.stringify(step.proposed_args)}`);
    console.log();
    console.log(gray(`approve with: vulnforge investigate exec ${id} ${step.index}`));
    return;
  }
  if (sub === 'exec') {
    const [id, idx] = args.positional.slice(1);
    if (!id || idx === undefined) { console.error('usage: vulnforge investigate exec <id> <step-index>'); return 1; }
    const step = await api(`/ai-investigate/sessions/${id}/execute/${idx}`, { method: 'POST', timeout: 300000 });
    console.log(bold(`Step ${step.index} -> ${step.status}`));
    if (step.result) { console.log(); console.log(step.result); }
    return;
  }
  console.error(`unknown subcommand: ${sub}`);
  return 1;
}

/**
 * Interactive chat REPL. Forwards each user line to /ai/chat along
 * with the full rolling conversation, so the server's AI router
 * (whatever provider is configured) can use context. Optional
 * --finding pulls that finding's context on start so the chat is
 * grounded in a specific record.
 */
async function cmdChat(args) {
  const messages = [];
  let systemHint = '';
  if (args.flags.finding) {
    try {
      const v = await api(`/vulnerabilities/${args.flags.finding}`);
      systemHint = `You are helping the user reason about finding #${v.id}: "${v.title}". ` +
                   `Severity ${v.severity}, file ${v.file}:${v.line_start ?? '?'}. ` +
                   `Description: ${(v.description || '').slice(0, 800)}`;
      console.log(gray(`Context: finding #${v.id} — ${v.title}`));
    } catch (err) {
      console.log(red(`Could not load finding ${args.flags.finding}: ${err.message}`));
    }
  }
  console.log(bold('VulnForge chat') + gray('  (ctrl-c or .exit to quit)'));
  console.log(gray('─'.repeat(60)));
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const prompt = () => rl.setPrompt(cyan('you> '));
  prompt();
  rl.prompt();

  for await (const line of rl) {
    const trimmed = line.trim();
    if (!trimmed) { rl.prompt(); continue; }
    if (trimmed === '.exit' || trimmed === '.quit') { rl.close(); break; }
    messages.push({ role: 'user', content: trimmed });
    try {
      const res = await api('/ai/chat', {
        method: 'POST',
        body: { messages, system: systemHint || undefined },
        timeout: 180000,
      });
      const reply = res.content || res.reply || (typeof res === 'string' ? res : '(no reply)');
      messages.push({ role: 'assistant', content: reply });
      console.log(`${blue('ai>')} ${reply}`);
    } catch (err) {
      console.log(red(`error: ${err.message}`));
      // Pop the user message so the history stays sane for retry.
      messages.pop();
    }
    rl.prompt();
  }
  console.log(gray('bye'));
}

function cmdConfig(args) {
  const sub = args.positional[0];
  const cfg = loadConfig();
  if (!sub || sub === 'show') {
    console.log(bold('cli config'));
    console.log(`  file:     ${CONFIG_FILE}`);
    console.log(`  api_base: ${cfg.api_base}`);
    console.log(`  token:    ${cfg.token ? cfg.token.slice(0, 8) + '…' : '(unset)'}`);
    console.log();
    console.log(gray('env overrides: VULNFORGE_API_BASE, VULNFORGE_TOKEN'));
    return;
  }
  if (sub === 'set') {
    const key = args.positional[1];
    const value = args.positional.slice(2).join(' ');
    if (!key || value === undefined) {
      console.error('usage: vulnforge config set <key> <value>');
      console.error('keys: api_base, token');
      return 1;
    }
    if (key !== 'api_base' && key !== 'token') {
      console.error(`unknown key: ${key}. allowed: api_base, token`);
      return 1;
    }
    cfg[key] = value;
    saveConfig(cfg);
    console.log(green(`saved ${key}`));
    return;
  }
  console.error(`unknown subcommand: ${sub}`);
  return 1;
}

// ── OpenClaw integration ──────────────────────────────────────────────────
//
// `vulnforge openclaw install` wires VulnForge's MCP server into
// OpenClaw's config so the agent immediately sees all 101 tools.
// Falls back to printing the JSON snippet if the openclaw CLI
// isn't on PATH - same file contents, operator pastes it manually.
//
// The actual helpers (URL normalisation, timeout choice, openclaw
// probing, port discovery, health ping) live in cli/openclaw.mjs so
// the unit tests can import them directly instead of re-deriving
// them from a replica that drifts over time.
//
// Flags:
//   --url <base>     override the MCP endpoint base. Skips port
//                    discovery — trust the operator's explicit value.
//                    Use this in team mode to point at a remote server.
//   --token <value>  attach as Authorization: Bearer <token>. Required
//                    when --url is non-loopback (team mode). This is
//                    a VulnForge API token (vf_…), not a JWT — mint
//                    one from Settings → API tokens.
//   --name <name>    entry name in openclaw.json (default: "vulnforge").
//                    Useful if you have multiple VulnForge instances.
//   --show-config    print the JSON we WOULD pass to openclaw, don't
//                    actually call it. Safe preview.
//
// Security notes:
// - When a token is present, the fallback "paste this" path and
//   `show-config` print the token in cleartext to stdout. That's
//   intentional (the user needs to paste it) but means the token
//   lands in terminal scrollback + any tee'd logs. On shared
//   systems, redirect stdout to a chmod-600 file instead of eyeballing.
// - `openclaw mcp set <name> <json>` puts the token in argv, which
//   is readable via `ps` / `/proc/<pid>/cmdline` to same-UID (and
//   sometimes root) processes for the duration of the spawn. If this
//   is a concern, use `--show-config` + manual paste instead.

/**
 * Pick the base URL for the install. Precedence:
 *
 *   1. Explicit --url flag (operator knows best; skip discovery).
 *   2. discoverVulnforgeOrigin() — resolves VULNFORGE_PORT env, then
 *      the .vulnforge-port file written by a running server, then
 *      probes the 3001-3010 range. Critical for dev mode where the
 *      server hops ports on EADDRINUSE.
 *   3. cfg.api_base as a last-resort fallback (may be stale, but the
 *      operator at least set it intentionally at some point).
 *   4. Hardcoded http://localhost:3001/api default.
 */
async function resolveOpenclawBaseUrl(cfg, urlFlag) {
  if (urlFlag) return urlFlag;
  const discovered = await discoverVulnforgeOrigin({ forceBase: cfg.api_base });
  if (discovered) return discovered;
  return cfg.api_base || 'http://localhost:3001/api';
}

/**
 * Print a prominent warning when the config we're about to dump to
 * stdout contains a real API token. We can't redact it (the user has
 * to paste the real value) but we can make the blast radius obvious
 * so they redirect to a chmod-600 file instead of just scrolling.
 */
function warnIfTokenInStdout(token) {
  if (!token) return;
  console.log(yellow('⚠ the output below contains your VulnForge API token in cleartext.'));
  console.log(gray('  treat terminal scrollback as equivalent to the token itself.'));
  console.log(gray('  if you are piping this to disk, use `... > openclaw.json && chmod 600 openclaw.json`.'));
  console.log();
}

async function cmdOpenclaw(sub, args) {
  if (sub === 'install') {
    const cfg = resolveConfig();
    const urlFlag = args.flags.url;
    const tokenFlag = args.flags.token;
    const name = String(args.flags.name || 'vulnforge');
    const showOnly = Boolean(args.flags['show-config']);

    const baseUrl = await resolveOpenclawBaseUrl(cfg, urlFlag);
    // If the caller didn't pass --token but the CLI already has one
    // configured, reuse it. That makes `vulnforge openclaw install`
    // just work right after a `vulnforge config set token ...`.
    const token = tokenFlag || cfg.token || '';

    // Fail fast when a remote install is missing a token — a no-auth
    // MCP entry pointing at a team server will 401 on every tool call,
    // which is a much worse UX than a clear error up front. Loopback
    // stays permissive because desktop mode genuinely runs without
    // auth.
    if (!isLoopbackUrl(baseUrl) && !String(token).trim()) {
      throw new Error(
        `remote openclaw installs require an API token. Pass --token <vf_...> ` +
        `or run "vulnforge config set token <vf_...>" before retrying. ` +
        `Mint a token in Settings → API tokens.`,
      );
    }

    // buildOpenclawMcpEntry picks the right connectionTimeoutMs itself
    // based on whether the normalised URL is loopback or remote.
    const entry = buildOpenclawMcpEntry({ url: baseUrl, token });

    if (showOnly) {
      console.log(bold('Would write this entry to openclaw.json → mcp.servers.' + name + ':'));
      console.log();
      warnIfTokenInStdout(token);
      console.log(JSON.stringify(entry, null, 2));
      return;
    }

    if (!openclawAvailable()) {
      console.log(yellow('openclaw CLI not found on PATH.'));
      console.log();
      warnIfTokenInStdout(token);
      console.log('To connect manually, paste this into your openclaw.json under "mcp.servers.' + name + '":');
      console.log();
      console.log(JSON.stringify(entry, null, 2));
      console.log();
      console.log(gray('Docs: docs/integrations/openclaw/README.md'));
      return;
    }

    // Note: when a token is set, `openclaw mcp set <name> <json>` exposes
    // it via argv for the duration of the spawn (visible to same-UID
    // processes via `ps` / `/proc/<pid>/cmdline`). OpenClaw's CLI doesn't
    // offer a stdin or file-based alternative. Security-sensitive users
    // should prefer `--show-config` and write the output to a chmod-600
    // file by hand. This is documented in
    // docs/integrations/openclaw/README.md § Security notes.
    const payload = JSON.stringify(entry);
    const r = spawnSync('openclaw', ['mcp', 'set', name, payload], {
      shell: false,
      stdio: 'inherit',
      encoding: 'utf8',
    });
    if (r.status !== 0) {
      throw new Error(`openclaw mcp set exited ${r.status}`);
    }
    console.log(green(`registered "${name}" with openclaw`));

    // Smoke the new entry via /api/health on the EXACT URL we just
    // wrote into the config (not the CLI's own cfg.api_base — that
    // would miss the common team-install case where --url points at
    // a remote host while the CLI is still configured for localhost).
    const ping = await pingVulnforgeBackend(baseUrl, { timeoutMs: 5000 });
    if (ping.ok) {
      const uptime = ping.uptime !== undefined ? ` (uptime ${Math.round(ping.uptime)}s)` : '';
      console.log(green('✓ vulnforge backend reachable at ') + gray(baseUrl) + gray(uptime));
    } else {
      console.log(yellow('⚠ vulnforge backend unreachable: ') + ping.error);
      console.log(gray('  the openclaw entry is written but calls will fail'));
      console.log(gray('  until the backend is running at ' + baseUrl));
    }
    return;
  }

  if (sub === 'show-config') {
    const cfg = resolveConfig();
    const baseUrl = await resolveOpenclawBaseUrl(cfg, args.flags.url);
    const token = args.flags.token || cfg.token || '';
    const name = String(args.flags.name || 'vulnforge');
    const entry = buildOpenclawMcpEntry({ url: baseUrl, token });
    warnIfTokenInStdout(token);
    console.log(JSON.stringify({ mcp: { servers: { [name]: entry } } }, null, 2));
    return;
  }

  console.error(red('usage:'));
  console.error('  vulnforge openclaw install [--url <base>] [--token <api-token>] [--name <entry>]');
  console.error('  vulnforge openclaw install --show-config   # print without calling openclaw');
  console.error('  vulnforge openclaw show-config [--name <entry>]  # print openclaw.json fragment');
  return 1;
}

function printHelp() {
  console.log(bold('vulnforge') + ' - CLI for the VulnForge API');
  console.log();
  console.log('Commands:');
  console.log('  ' + cyan('status') + '                         Server health + active pipelines');
  console.log('  ' + cyan('findings') + ' [filters]             List findings (--severity --status --search --limit)');
  console.log('  ' + cyan('finding') + ' <id>                   Show a finding with full detail');
  console.log('  ' + cyan('hunt') + ' <url|path> [--branch]     Start a pipeline + stream progress');
  console.log('  ' + cyan('triage') + ' <id>                    Run AI triage on one finding');
  console.log('  ' + cyan('deep-triage') + ' <id>               Run 4-stage deep triage on one finding');
  console.log('  ' + cyan('investigate list') + '               List investigation sessions');
  console.log('  ' + cyan('investigate new') + ' "<goal>"       Start a new session (--finding=N to link)');
  console.log('  ' + cyan('investigate step') + ' <id>          Ask AI for the next step');
  console.log('  ' + cyan('investigate exec') + ' <id> <idx>    Execute a proposed step');
  console.log('  ' + cyan('chat') + ' [--finding=N]             Interactive chat with the AI');
  console.log('  ' + cyan('openclaw install') + '              Wire vulnforge into OpenClaw (--url --token --name)');
  console.log('  ' + cyan('openclaw show-config') + '          Print the openclaw.json fragment without installing');
  console.log('  ' + cyan('config show') + '                    Print current CLI config');
  console.log('  ' + cyan('config set') + ' <key> <value>       Set api_base or token');
  console.log();
  console.log(gray('Config file: ' + CONFIG_FILE));
  console.log(gray('Env vars:    VULNFORGE_API_BASE, VULNFORGE_TOKEN'));
}

// ── Main ─────────────────────────────────────────────────────────────────

async function main() {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h') { printHelp(); return; }
  const [cmd, ...rest] = argv;
  const args = parseArgs(rest);

  try {
    switch (cmd) {
      case 'status':       return await cmdStatus();
      case 'findings':     return await cmdFindings(args);
      case 'finding':      return await cmdFinding(args.positional[0]);
      case 'hunt':         return await cmdHunt(args.positional[0], args);
      case 'triage':       return await cmdTriage(args.positional[0]);
      case 'deep-triage':  return await cmdTriage(args.positional[0], { deep: true });
      case 'investigate':  return await cmdInvestigate(args.positional[0], args);
      case 'chat':         return await cmdChat(args);
      case 'openclaw':     return await cmdOpenclaw(args.positional[0] || 'install', args);
      case 'config':       return cmdConfig(args);
      default:
        console.error(red(`unknown command: ${cmd}`));
        console.error(`run ${cyan('vulnforge --help')} for usage`);
        return 1;
    }
  } catch (err) {
    console.error(red(`error: ${err.message || err}`));
    if (process.env.VULNFORGE_DEBUG) console.error(err);
    return 1;
  }
}

const code = await main();
process.exit(code || 0);
