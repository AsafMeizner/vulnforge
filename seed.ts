/**
 * VulnForge seed script
 * Populates: tools, projects, vulnerabilities (migrated from old dashboard), AI providers
 */

import { readFileSync, existsSync, readdirSync, statSync } from 'fs';
import path from 'path';
import { initDb, upsertTool, createProject, createVulnerability, upsertAIProvider, getAllProjects, getAllVulnerabilities } from './server/db.js';
import { loadAllChecklists } from './server/checklists/loader.js';

const TOOLS_DIR = 'X:/security-solver/tools';
const TARGETS_DIR = 'X:/security-solver/targets';
const DISCLOSURES_DIR = 'X:/security-solver/disclosures';

// ── Helper: extract Python docstring ──────────────────────────────────────

function extractDocstring(filePath: string): { full: string; firstLine: string } {
  try {
    const content = readFileSync(filePath, { encoding: 'utf8' });
    const match = content.match(/"""([\s\S]*?)"""/);
    if (match) {
      const full = match[1].trim();
      const firstLine = full.split('\n')[0].trim();
      return { full, firstLine };
    }
  } catch {
    // ignore
  }
  return { full: '', firstLine: '' };
}

// ── Helper: categorize tool ────────────────────────────────────────────────

function categorizeTool(name: string): string {
  if (/integer|overflow|truncat|cross_arch/.test(name)) return 'integer';
  if (/signal|race|concurren|atomic/.test(name)) return 'concurrency';
  if (/crypto|timing|oracle/.test(name)) return 'crypto';
  if (/supply_chain|dependency/.test(name)) return 'supply-chain';
  if (/uaf|double_free|realloc|dangl/.test(name)) return 'memory';
  if (/parser|complexity|taint|flow/.test(name)) return 'analysis';
  if (/preauth|auth_bypass/.test(name)) return 'auth';
  if (/smuggling|protocol/.test(name)) return 'protocol';
  if (/dangerous|format|pattern/.test(name)) return 'dangerous-patterns';
  if (/null_deref|boundary|bounds/.test(name)) return 'memory';
  if (/command|injection/.test(name)) return 'injection';
  if (/stack|vla|clash/.test(name)) return 'memory';
  return 'static-analysis';
}

// ── Helper: track record from old dashboard ────────────────────────────────

const TRACK_RECORDS: Record<string, string> = {
  cross_arch_truncation: 'Found libarchive CRITICAL',
  integer_overflow_scanner: 'Found jq CRITICAL',
  signal_safety_checker: 'Found Redis + systemd',
  parser_complexity_scorer: 'Guided targeting',
  signed_unsigned_checker: 'NEW',
  timing_oracle_scanner: 'NEW',
  realloc_dangling_scanner: 'NEW',
  deserialization_trust_scanner: 'Found gravity, mruby, pcre2, v7',
  protocol_smuggling_scanner: 'Found civetweb CL.TE, libevent',
  double_free_scanner: '',
  ub_compiler_trap_scanner: '',
  recursive_bomb_scanner: '',
  taint_flow_analyzer: '',
  state_machine_scanner: '',
  stack_clash_vla_scanner: '',
  crypto_misuse_scanner: '',
  preauth_tracer: '',
  supply_chain_scanner: '',
  uaf_detector: '',
  dangerous_patterns: '',
};

// ── Helper: read disclosure content ───────────────────────────────────────

function readDisclosureContent(disclosureKey: string): { disclosure: string; howToSubmit: string } {
  if (!disclosureKey) return { disclosure: '', howToSubmit: '' };

  // disclosureKey is like "jq/disclosure-1-submitted.md"
  const discPath = path.join(DISCLOSURES_DIR, disclosureKey);
  const project = disclosureKey.split('/')[0];
  const howToPath = path.join(DISCLOSURES_DIR, project, 'how_to_submit.md');

  let disclosure = '';
  let howToSubmit = '';

  try {
    if (existsSync(discPath)) {
      disclosure = readFileSync(discPath, { encoding: 'utf8' });
    }
  } catch {
    // File may not exist for all entries
  }

  try {
    if (existsSync(howToPath)) {
      howToSubmit = readFileSync(howToPath, { encoding: 'utf8' });
    }
  } catch {
    // Optional
  }

  return { disclosure, howToSubmit };
}

// ── Seed: Tools ────────────────────────────────────────────────────────────

async function seedTools(): Promise<void> {
  console.log('\n[Seed] Seeding tools from', TOOLS_DIR);
  let count = 0;

  const files = readdirSync(TOOLS_DIR).filter(f => f.endsWith('.py'));

  for (const file of files) {
    const name = path.basename(file, '.py');
    const filePath = path.join(TOOLS_DIR, file);
    const { full: docs, firstLine: description } = extractDocstring(filePath);
    const category = categorizeTool(name);
    const track_record = TRACK_RECORDS[name] ?? '';

    upsertTool({
      name,
      category,
      description: description || name,
      docs: docs || '',
      track_record,
      file_path: filePath,
      enabled: 1,
    });
    count++;
  }

  console.log(`[Seed] Seeded ${count} tools`);
}

// ── Seed: Projects ─────────────────────────────────────────────────────────

async function seedProjects(): Promise<Map<string, number>> {
  console.log('\n[Seed] Seeding projects from', TARGETS_DIR);
  const nameToId = new Map<string, number>();

  // Check existing projects to avoid duplicates
  const existing = getAllProjects();
  for (const p of existing) {
    nameToId.set(p.name.toLowerCase(), p.id!);
  }

  if (!existsSync(TARGETS_DIR)) {
    console.warn('[Seed] Targets directory not found, skipping projects');
    return nameToId;
  }

  const entries = readdirSync(TARGETS_DIR, { withFileTypes: true });
  let count = 0;

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const name = entry.name;
    const dirPath = path.join(TARGETS_DIR, name);

    if (nameToId.has(name.toLowerCase())) {
      // Already seeded
      continue;
    }

    // Detect language from file extensions
    const language = detectLanguage(dirPath);

    const id = createProject({
      name,
      path: dirPath,
      language,
    });

    nameToId.set(name.toLowerCase(), id);
    count++;
  }

  console.log(`[Seed] Seeded ${count} projects (${nameToId.size} total including existing)`);
  return nameToId;
}

function detectLanguage(dirPath: string): string {
  const extCounts: Record<string, number> = {};
  const langMap: Record<string, string> = {
    '.c': 'C', '.h': 'C', '.cpp': 'C++', '.cc': 'C++', '.cxx': 'C++',
    '.hpp': 'C++', '.py': 'Python', '.js': 'JavaScript', '.ts': 'TypeScript',
    '.go': 'Go', '.rs': 'Rust', '.java': 'Java', '.rb': 'Ruby',
  };

  function scan(dir: string, depth: number): void {
    if (depth > 2) return;
    try {
      const items = readdirSync(dir, { withFileTypes: true });
      for (const item of items) {
        if (item.name.startsWith('.') || item.name === 'node_modules') continue;
        if (item.isFile()) {
          const ext = path.extname(item.name).toLowerCase();
          const lang = langMap[ext];
          if (lang) extCounts[lang] = (extCounts[lang] || 0) + 1;
        } else if (item.isDirectory()) {
          scan(path.join(dir, item.name), depth + 1);
        }
      }
    } catch {
      // ignore
    }
  }

  scan(dirPath, 0);
  const sorted = Object.entries(extCounts).sort(([, a], [, b]) => b - a);
  return sorted[0]?.[0] || 'C';
}

// ── Vulnerability data from old dashboard ─────────────────────────────────

const OLD_VULNS = [
  {id:1,project:"libarchive",title:"uint64 to size_t truncation in malloc (32-bit)",severity:"Critical",status:"Submitted",cvss:"9.8",cvssVector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",cwe:"CWE-681",method:"Integer overflow scanner",advisory:"GHSA-rf5v-vf7c-6wvg",advisoryUrl:"https://github.com/libarchive/libarchive/security/advisories/GHSA-rf5v-vf7c-6wvg",file:"archive_read_support_format_7zip.c:3932",notes:"",response:"",submitTo:"GitHub Security Advisory",submitEmail:"",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"libarchive/disclosure-1-submitted.md"},
  {id:2,project:"jq",title:"uint32 overflow in jvp_string_copy_replace_bad",severity:"High",status:"Submitted",cvss:"8.1",cvssVector:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",cwe:"CWE-190",method:"Integer overflow scanner",advisory:"GHSA-5v73-72wr-p73g",advisoryUrl:"https://github.com/jqlang/jq/security/advisories/GHSA-5v73-72wr-p73g",file:"src/jv.c:1117",notes:"",response:"",submitTo:"GitHub Security Advisory",submitEmail:"",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"jq/disclosure-1-submitted.md"},
  {id:3,project:"jq",title:"String append buffer overflow",severity:"High",status:"Submitted",cvss:"7.5",cvssVector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",cwe:"CWE-122",method:"Manual audit",advisory:"",advisoryUrl:"",file:"src/jv.c",notes:"",response:"",submitTo:"GitHub Security Advisory",submitEmail:"",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"jq/disclosure-2-submitted.md"},
  {id:4,project:"jq",title:"HashDoS via hardcoded hash seed",severity:"Medium",status:"Submitted",cvss:"5.3",cvssVector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",cwe:"CWE-328",method:"Manual audit",advisory:"",advisoryUrl:"",file:"src/jv.c:1200",notes:"",response:"",submitTo:"GitHub Security Advisory",submitEmail:"",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"jq/disclosure-3-submitted.md"},
  {id:5,project:"mongoose",title:"TLS: hardcoded session_id + DER bounds + cert chain",severity:"High",status:"Submitted",cvss:"7.4",cvssVector:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",cwe:"CWE-295",method:"Manual audit",advisory:"",advisoryUrl:"",file:"src/tls_builtin.c",notes:"",response:"",submitTo:"Email",submitEmail:"support@cesanta.com",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"mongoose/disclosure-1-submitted.md"},
  {id:6,project:"civetweb",title:"CL.TE request smuggling",severity:"Critical",status:"Submitted",cvss:"10.0",cvssVector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",cwe:"CWE-444",method:"Differential: nginx vs civetweb",advisory:"",advisoryUrl:"",file:"civetweb.c:19203",notes:"",response:"",submitTo:"Email",submitEmail:"bel2125@gmail.com",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"civetweb/disclosure-1-submitted.md"},
  {id:7,project:"civetweb",title:"NUL byte (%00) URI truncation",severity:"Critical",status:"Submitted",cvss:"9.8",cvssVector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",cwe:"CWE-158",method:"Differential: nginx vs civetweb",advisory:"",advisoryUrl:"",file:"civetweb.c:7283",notes:"Included in disclosure-1",submitTo:"Email",submitEmail:"bel2125@gmail.com",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"civetweb/disclosure-1-submitted.md"},
  {id:8,project:"civetweb",title:"WebSocket decompression bomb + 32-bit heap overflow",severity:"Critical",status:"Ready",cvss:"9.1",cvssVector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",cwe:"CWE-190",method:"Manual: inflate pattern",advisory:"",advisoryUrl:"",file:"civetweb.c:13688-13745",notes:"inflate_buf_size *= 2 overflows on 32-bit",submitTo:"Email",submitEmail:"bel2125@gmail.com",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"civetweb/disclosure-2.md"},
  {id:9,project:"libssh2",title:"WINDOW_ADJUST integer overflow (curl, git)",severity:"High",status:"Submitted",cvss:"7.1",cvssVector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H",cwe:"CWE-190",method:"Differential: OpenSSH vs libssh2",advisory:"",advisoryUrl:"",file:"packet.c:1356",notes:"",response:"",submitTo:"Email",submitEmail:"libssh2-security@haxx.se",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"libssh2/disclosure-1-submitted.md"},
  {id:10,project:"wolfSSL",title:"pathLen bypass + empty record flood + dup extension",severity:"High",status:"Fixed",cvss:"7.4",cvssVector:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",cwe:"CWE-295",method:"Differential: wolfSSL vs OpenSSL",advisory:"PR #10187",advisoryUrl:"https://github.com/wolfSSL/wolfssl/pull/10187",file:"asn.c:22428",notes:"Fixed same day",response:"Eric Blankenhorn responded same day with PR #10187 fixing all 3 issues with tests. Reviewed and confirmed fixes are correct.",submitTo:"Email",submitEmail:"support@wolfssl.com",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"wolfssl/disclosure-1-submitted.md"},
  {id:11,project:"gravity",title:"VM bytecode 3-class validation bypass",severity:"Critical",status:"Submitted",cvss:"8.8",cvssVector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",cwe:"CWE-787",method:"Bytecode validation pattern",advisory:"",advisoryUrl:"",file:"gravity_vm.c, gravity_value.c",notes:"register/cpool/jump OOB",submitTo:"Email",submitEmail:"marco@creolabs.com",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"gravity/disclosure-1-submitted.md"},
  {id:12,project:"contiki-ng",title:"MQTT PUBLISH topic buffer overflow",severity:"High",status:"Submitted",cvss:"8.1",cvssVector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",cwe:"CWE-120",method:"IoT protocol parser audit",advisory:"",advisoryUrl:"",file:"mqtt.c:1215",notes:"",response:"",submitTo:"Email",submitEmail:"security@contiki-ng.org",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"contiki-ng/disclosure-1-submitted.md"},
  {id:13,project:"libhv",title:"DNS name decompression stack overflow",severity:"High",status:"Submitted",cvss:"8.6",cvssVector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H",cwe:"CWE-121",method:"IoT protocol parser audit",advisory:"",advisoryUrl:"",file:"protocol/dns.c:45",notes:"",response:"",submitTo:"Email",submitEmail:"ithewei@163.com",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"libhv/disclosure-1-submitted.md"},
  {id:14,project:"redis",title:"Signal handler async-signal-unsafe",severity:"Medium",status:"Submitted",cvss:"5.9",cvssVector:"CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",cwe:"CWE-479",method:"Signal handler analysis",advisory:"",advisoryUrl:"",file:"debug.c:2448",notes:"crash handler + double-SIGINT exit(1)",submitTo:"Email",submitEmail:"redis@redis.io",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"redis/disclosure-1-submitted.md"},
  {id:15,project:"rt-thread",title:"DHCP server unbounded option parsing",severity:"High",status:"Submitted",cvss:"7.1",cvssVector:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H",cwe:"CWE-125",method:"IoT protocol parser audit",advisory:"",advisoryUrl:"",file:"dhcp_server.c:346",notes:"",response:"",submitTo:"GitHub Security Advisory",submitEmail:"",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"rt-thread/disclosure-1-submitted.md"},
  {id:16,project:"stb",title:"Animated GIF layers*stride integer overflow",severity:"High",status:"Submitted",cvss:"7.1",cvssVector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H",cwe:"CWE-190",method:"Integer overflow in parsing",advisory:"",advisoryUrl:"",file:"stb_image.h:6994",notes:"",response:"",submitTo:"Public GitHub Issue",submitEmail:"",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"stb/disclosure-1-submitted.md"},
  {id:17,project:"pcre2",title:"Serialization buffer over-read (no length param)",severity:"Medium",status:"Submitted",cvss:"6.1",cvssVector:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H",cwe:"CWE-125",method:"Binary format validation",advisory:"",advisoryUrl:"",file:"pcre2_serialize.c:160",notes:"",response:"",submitTo:"GitHub Security Advisory",submitEmail:"",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"pcre2/disclosure-1-submitted.md"},
  {id:18,project:"c-ares",title:"CNAME chain DoS + pointer hops + dup OPT",severity:"High",status:"Partial",cvss:"7.5",cvssVector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",cwe:"CWE-770",method:"Differential: c-ares vs unbound",advisory:"",advisoryUrl:"",file:"",notes:"",response:"",submitTo:"Email",submitEmail:"c-ares-security@haxx.se",emailChainUrl:"",issueUrl:"",rejectionReason:"CNAME chain: maintainer says c-ares already has limits. Pointer hops: accepted as improvement. Duplicate OPT: filed as normal issue.",subFindings:"CNAME chain DoS: Rejected (already handled)\nPointer hop limit: Working on fix\nDuplicate OPT: Filed as GitHub issue",disclosureKey:"c-ares/disclosure-1-closed.md"},
  {id:19,project:"libevent",title:"CL.TE request smuggling (Tor, memcached)",severity:"Critical",status:"Ready",cvss:"10.0",cvssVector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",cwe:"CWE-444",method:"Manual: CL+TE pattern",advisory:"",advisoryUrl:"https://github.com/libevent/libevent/security/advisories/new",file:"http.c:2384-2388",notes:"Affects Tor, memcached, tmux. Also: %00 URI truncation + obs-fold",submitTo:"GitHub Security Advisory",submitEmail:"",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"libevent/disclosure-1.md"},
  {id:20,project:"libyaml",title:"yaml_string_extend overflow on 32-bit",severity:"High",status:"Ready",cvss:"7.0",cvssVector:"CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",cwe:"CWE-190",method:"Deep audit agent",advisory:"",advisoryUrl:"https://github.com/yaml/libyaml/security/advisories/new",file:"api.c:76",notes:"stack_extend has guard, string_extend doesn't",submitTo:"GitHub Security Advisory",submitEmail:"",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"libyaml/disclosure-1.md"},
  {id:21,project:"libexpat",title:"No element depth limit + billion-laughs threshold bypass",severity:"High",status:"Ready",cvss:"7.5",cvssVector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",cwe:"CWE-776",method:"Differential: libexpat vs libxml2",advisory:"",advisoryUrl:"",file:"xmlparse.c",notes:"libxml2 limits 256, expat has 0. 90-day embargo requested.",submitTo:"Email",submitEmail:"sebastian@pipping.org",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"libexpat/disclosure-1.md"},
  {id:22,project:"jansson",title:"Unbounded recursion in json_dumps/json_deep_copy",severity:"Medium",status:"Ready",cvss:"5.5",cvssVector:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",cwe:"CWE-674",method:"Deep audit agent",advisory:"",advisoryUrl:"https://github.com/akheron/jansson/security/advisories/new",file:"dump.c:215",notes:"Parser limits 2048, serializer has no limit",submitTo:"GitHub Security Advisory",submitEmail:"",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"jansson/disclosure-1.md"},
  {id:23,project:"picotls",title:"Operator precedence bug in on_extension (6 sites)",severity:"Medium",status:"Ready",cvss:"5.3",cvssVector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",cwe:"CWE-783",method:"TLS handshake audit",advisory:"",advisoryUrl:"https://github.com/h2o/picotls/security/advisories/new",file:"picotls.c:2645",notes:"ret = cb() != 0 parsed as ret = (cb() != 0)",submitTo:"GitHub Security Advisory",submitEmail:"",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"picotls/disclosure-1.md"},
  {id:24,project:"cosmopolitan",title:"ZIP filesystem: 4 integer overflow / bounds bugs",severity:"High",status:"Ready",cvss:"7.0",cvssVector:"CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",cwe:"CWE-190",method:"Deep audit agent",advisory:"",advisoryUrl:"https://github.com/jart/cosmopolitan/issues/new",file:"zipos-open.c:59",notes:"Affects redbean web server",submitTo:"GitHub Issue",submitEmail:"",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"cosmopolitan/disclosure-1.md"},
  {id:25,project:"libwebsockets",title:"Server ignores chunked TE + WS frame truncation",severity:"Medium",status:"Ready",cvss:"6.5",cvssVector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",cwe:"CWE-444",method:"Differential: libevent vs libwebsockets",advisory:"",advisoryUrl:"https://github.com/warmcat/libwebsockets/security/advisories/new",file:"server.c:1719",notes:"",response:"",submitTo:"GitHub Security Advisory",submitEmail:"",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"libwebsockets/disclosure-1.md"},
  {id:26,project:"SQLite",title:"FTS5 fts5DlidxLvlPrev heap over-read",severity:"High",status:"Ready",cvss:"7.1",cvssVector:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H",cwe:"CWE-125",method:"Deep audit agent",advisory:"",advisoryUrl:"",file:"fts5_index.c:1706",notes:"Forward has bounds check, reverse doesn't",submitTo:"Email",submitEmail:"drh@sqlite.org",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"sqlite/disclosure-1.md"},
  {id:27,project:"SQLite",title:"FTS5 fts5DataRead unvalidated szLeaf",severity:"High",status:"Ready",cvss:"7.1",cvssVector:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H",cwe:"CWE-125",method:"Deep audit agent",advisory:"",advisoryUrl:"",file:"fts5_index.c:901",notes:"TODO1 comment acknowledges",submitTo:"Email",submitEmail:"drh@sqlite.org",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"sqlite/disclosure-1.md"},
  {id:28,project:"Node.js",title:"DNS SOA OOB read (disproved)",severity:"Low",status:"Rejected",cvss:"",cvssVector:"",cwe:"CWE-125",method:"Manual audit",advisory:"",advisoryUrl:"",file:"cares_wrap.cc:808",notes:"mcollina could not reproduce",response:"I tried your example and I could not reproduce. ares_expand_name() at deps/cares/src/lib/legacy/ares_expand_name.c:49 checks bounds.",submitTo:"Slack DM",submitEmail:"",emailChainUrl:"",issueUrl:"",rejectionReason:"ares_expand_name() validates bounds at line 49. The OOB read claim was incorrect — the function returns ARES_EBADNAME before reaching the vulnerable path.",subFindings:"",disclosureKey:"nodejs/disclosure-1-REJECTED.md"},
  {id:29,project:"OpenSSH",title:"Compat flag injection via MONITOR_REQ_SETCOMPAT",severity:"Low",status:"Rejected",cvss:"",cvssVector:"",cwe:"",method:"Manual audit",advisory:"",advisoryUrl:"",file:"monitor.c",notes:"MON_ONCE flag prevents re-setting",response:"Damien Miller explained the handler has MON_ONCE flag preventing re-setting. Banner parsing in unprivileged child is unconditionally better than the alternative.",submitTo:"Email",submitEmail:"openssh-unix-dev@mindrot.org",emailChainUrl:"",issueUrl:"",rejectionReason:"MON_ONCE flag on MONITOR_REQ_SETCOMPAT handler prevents the compat flags from being re-set after initial use. Intentional design — banner parsing in unprivileged child is safer.",subFindings:"",disclosureKey:"openssh/disclosure-1-REJECTED.md"},
  {id:30,project:"OpenSSH",title:"Sandbox/privsep bypass attempt",severity:"Low",status:"Rejected",cvss:"",cvssVector:"",cwe:"",method:"Manual audit",advisory:"",advisoryUrl:"",file:"",notes:"Intentional design decision",response:"",submitTo:"Email",submitEmail:"openssh-unix-dev@mindrot.org",emailChainUrl:"",issueUrl:"",rejectionReason:"Intentional design. The privsep architecture is working as intended.",subFindings:"",disclosureKey:"openssh/disclosure-2-REJECTED.md"},
  {id:31,project:"Linux kernel",title:"io_uring RCU race condition",severity:"Low",status:"Rejected",cvss:"",cvssVector:"",cwe:"",method:"Manual audit",advisory:"",advisoryUrl:"",file:"io_uring/",notes:"Jens Axboe: locks protect the race",response:"Jens Axboe explained fdinfo holds uring_lock/completion_lock preventing the free, and resize is DEFER_TASKRUN only (excludes SQPOLL).",submitTo:"Email",submitEmail:"security@kernel.org",emailChainUrl:"",issueUrl:"",rejectionReason:"The uring_lock and completion_lock protect the access pattern. The DEFER_TASKRUN constraint excludes SQPOLL, eliminating the race window.",subFindings:"",disclosureKey:"linux-kernel/disclosure-1-REJECTED.md"},
  {id:32,project:"systemd",title:"PID 1 crash handler async-signal-unsafe",severity:"Medium",status:"Closed",cvss:"5.9",cvssVector:"CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H",cwe:"CWE-479",method:"Signal handler analysis",advisory:"GHSA-23pg-4gfj-vw5x",advisoryUrl:"",file:"crash-handler.c:60",notes:"Maintainer closed: design trade-off for crash diagnostics",response:"bluca: That is not a real world reproducer. Closing since with no reproducer there is no valid security issue.",submitTo:"GitHub Security Advisory",submitEmail:"systemd-security@redhat.com",emailChainUrl:"",issueUrl:"",rejectionReason:"Maintainer considers this an acceptable design trade-off: crash diagnostics outweigh theoretical signal-safety risk. Requested real-world reproducer; our sendmsg-blocking reproducer was considered artificial.",subFindings:"",disclosureKey:"systemd/disclosure-1-submitted.md"},
  {id:33,project:"mruby",title:"Bytecode loader overflow + VM operand validation",severity:"Medium",status:"Out of Scope",cvss:"7.0",cvssVector:"CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",cwe:"CWE-787",method:"Bytecode validation pattern",advisory:"",advisoryUrl:"",file:"load.c:449, vm.c",notes:"Filed as bug report, NOT security",response:"",submitTo:"Bug report at GitHub Issues",submitEmail:"matz@ruby.or.jp",emailChainUrl:"",issueUrl:"",rejectionReason:"mruby SECURITY.md explicitly states: 'Crashes from Malformed Bytecode are NOT considered security vulnerabilities. mruby bytecode format is not a security boundary.'",subFindings:"",disclosureKey:"mruby/disclosure-1-OUT-OF-SCOPE.md"},
  {id:34,project:"v7",title:"JS engine bytecode deserialization bypass",severity:"High",status:"Closed",cvss:"8.8",cvssVector:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",cwe:"CWE-787",method:"Bytecode validation pattern",advisory:"",advisoryUrl:"",file:"v7.c:15312",notes:"Project appears deprecated in favor of mJS",response:"",submitTo:"Email",submitEmail:"support@cesanta.com",emailChainUrl:"",issueUrl:"",rejectionReason:"Project appears deprecated/archived. Sent to Cesanta but no response expected.",subFindings:"",disclosureKey:"v7/disclosure-1-DEPRICATED.md"},
  {id:35,project:"nghttp2",title:"HTTP/2 findings",severity:"Medium",status:"Submitted",cvss:"",cvssVector:"",cwe:"",method:"Protocol audit",advisory:"",advisoryUrl:"",file:"",notes:"Submitted via contiki",response:"",submitTo:"GitHub",submitEmail:"",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"",disclosureKey:"nghttp2/disclosure-1-submitted.md"},
  {id:36,project:"Node.js",title:"Permission model + crypto findings",severity:"Low",status:"Ready",cvss:"",cvssVector:"",cwe:"",method:"Deep hunt agent",advisory:"",advisoryUrl:"",file:"fs_permission.cc, crypto_context.cc",notes:"5 findings from deep hunt, all Tier C. Best: WildcardIfDir uv_fs_req_cleanup leak.",response:"",submitTo:"HackerOne",submitEmail:"",emailChainUrl:"",issueUrl:"",rejectionReason:"",subFindings:"F-01 WildcardIfDir leak: Tier C (quality bug)\nF-02 RadixTree case on Windows: Tier C (over-restriction not bypass)\nF-03 InternalModuleStat: Tier C (limited info leak)\nF-04 NextNode loop bound: Tier C (no demonstrated bypass)\nF-05 SSL SetOptions truncation: Tier C (64-bit safe)",disclosureKey:"node/disclosure-1.md"},
];

// Normalize project name for lookup (handles case/alias differences)
function normalizeProjectName(name: string): string {
  const aliases: Record<string, string> = {
    'sqlite': 'sqlite',
    'wolfssl': 'wolfssl',
    'node.js': 'node',
    'linux kernel': 'linux-kernel', // no target dir, but disclosure exists
    'contiki-ng': 'contiki',
    'rt-thread': 'rt-thread',
  };
  const lower = name.toLowerCase();
  return aliases[lower] || lower;
}

// ── Seed: Vulnerabilities ─────────────────────────────────────────────────

async function seedVulnerabilities(projectNameToId: Map<string, number>): Promise<void> {
  console.log('\n[Seed] Seeding vulnerabilities from old dashboard...');

  // Check if already seeded
  const existing = getAllVulnerabilities({ limit: 1 });
  if (existing.length > 0) {
    console.log('[Seed] Vulnerabilities already seeded, skipping');
    return;
  }

  let count = 0;
  let skipped = 0;

  for (const v of OLD_VULNS) {
    // Resolve project_id
    const normalizedProject = normalizeProjectName(v.project);
    const projectId = projectNameToId.get(normalizedProject) ||
                      projectNameToId.get(v.project.toLowerCase()) ||
                      undefined;

    if (!projectId) {
      console.warn(`[Seed] No project found for "${v.project}" (normalized: "${normalizedProject}") — creating standalone entry`);
    }

    // Read disclosure content
    const { disclosure, howToSubmit } = readDisclosureContent(v.disclosureKey || '');

    // Parse file location
    let file: string | undefined;
    let lineStart: number | undefined;
    let lineEnd: number | undefined;
    if (v.file) {
      const lineMatch = v.file.match(/^(.+?):(\d+)(?:-(\d+))?$/);
      if (lineMatch) {
        file = lineMatch[1];
        lineStart = parseInt(lineMatch[2], 10);
        if (lineMatch[3]) lineEnd = parseInt(lineMatch[3], 10);
      } else {
        file = v.file;
      }
    }

    try {
      createVulnerability({
        project_id: projectId,
        title: v.title,
        severity: v.severity,
        status: v.status,
        cvss: v.cvss || undefined,
        cvss_vector: v.cvssVector || undefined,
        cwe: v.cwe || undefined,
        file,
        line_start: lineStart,
        line_end: lineEnd,
        method: v.method || undefined,
        advisory: v.advisory || undefined,
        advisory_url: v.advisoryUrl || undefined,
        submit_to: v.submitTo || undefined,
        submit_email: v.submitEmail || undefined,
        email_chain_url: v.emailChainUrl || undefined,
        issue_url: v.issueUrl || undefined,
        response: v.response || undefined,
        rejection_reason: v.rejectionReason || undefined,
        sub_findings: v.subFindings || undefined,
        description: v.notes || undefined,
        disclosure_content: disclosure || undefined,
        how_to_submit_content: howToSubmit || undefined,
        verified: ['Submitted', 'Fixed', 'Responded', 'HackerOne', 'Partial'].includes(v.status) ? 1 : 0,
      });
      count++;
    } catch (err) {
      console.error(`[Seed] Failed to insert vuln "${v.title}":`, err);
      skipped++;
    }
  }

  console.log(`[Seed] Seeded ${count} vulnerabilities (${skipped} failed)`);
}

// ── Seed: AI Providers ────────────────────────────────────────────────────

async function seedAIProviders(): Promise<void> {
  console.log('\n[Seed] Seeding AI providers...');

  const providers = [
    { name: 'ollama', model: 'llama3.2', base_url: 'http://localhost:11434', enabled: 1, api_key: '' },
    { name: 'claude', model: 'claude-sonnet-4-20250514', enabled: 0, api_key: '' },
    { name: 'openai', model: 'gpt-4o', enabled: 0, api_key: '' },
  ];

  for (const p of providers) {
    upsertAIProvider(p);
  }

  console.log(`[Seed] Seeded ${providers.length} AI providers`);
}

// ── Main ──────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log('=================================================');
  console.log('  VulnForge Seed Script');
  console.log('=================================================');

  // Initialize DB
  console.log('\n[Seed] Initializing database...');
  await initDb();
  console.log('[Seed] Database ready');

  // Seed in order
  await seedTools();
  const projectNameToId = await seedProjects();
  await seedVulnerabilities(projectNameToId);
  await seedAIProviders();

  // Load checklist definitions from JSON files
  console.log('\n[Seed] Loading checklists from /checklists/ ...');
  const checklistsInserted = await loadAllChecklists();
  console.log(`[Seed] ${checklistsInserted} checklists loaded`);

  console.log('\n=================================================');
  console.log('  Seed complete!');
  console.log('=================================================\n');
}

main().catch(err => {
  console.error('[Seed] Fatal error:', err);
  process.exit(1);
});
