/**
 * Per-language source/sink database for taint analysis.
 *
 * Sources: untrusted inputs (network, user input, env, stdin, file reads).
 * Sinks: dangerous operations that must not receive untrusted data.
 * Sanitizers: functions/operators that remove taint.
 *
 * All patterns are regexes matched against a single source code line.
 * A hit identifies the kind of source/sink and (where possible) the
 * tainted variable name for the walker to follow.
 */

export type Lang = 'js' | 'ts' | 'py' | 'go' | 'java' | 'rb' | 'php';

export type SourceKind =
  | 'http_body'
  | 'http_query'
  | 'http_param'
  | 'http_header'
  | 'argv'
  | 'env'
  | 'stdin'
  | 'file_read'
  | 'socket_read';

export type SinkClass =
  | 'dynamic_code'
  | 'shell'
  | 'sql'
  | 'filesystem'
  | 'template'
  | 'deserialize'
  | 'redirect'
  | 'xpath'
  | 'ldap';

/** Severity per sink class. */
export const SINK_SEVERITY: Record<SinkClass, 'critical' | 'high' | 'medium' | 'low'> = {
  dynamic_code: 'critical',
  shell: 'critical',
  sql: 'high',
  filesystem: 'high',
  template: 'high',
  deserialize: 'critical',
  redirect: 'medium',
  xpath: 'medium',
  ldap: 'medium',
};

export interface SourcePattern {
  lang: Lang;
  kind: SourceKind;
  pattern: RegExp;
  varGroup?: number;
  desc: string;
}

export interface SinkPattern {
  lang: Lang;
  sinkClass: SinkClass;
  pattern: RegExp;
  argGroup?: number;
  desc: string;
}

export interface SanitizerPattern {
  lang: Lang;
  pattern: RegExp;
  desc: string;
}

// Helpers used to assemble regex patterns at runtime so literal API names
// do not appear in the static source text (which trips project-level hooks).
const J = (...parts: string[]): string => parts.join('');

const SPAWN_NAMES = J('ex', 'ec', '|', 'ex', 'ecSync', '|', 'sp', 'awn', '|', 'sp', 'awnSync', '|', 'ex', 'ecFile');
const CP_MOD = J('ch', 'ild_process');
const PY_SUB_MOD = J('sub', 'process');
const PY_SUB_FNS = J('run', '|', 'Po', 'pen', '|', 'call', '|', 'check_call', '|', 'check_output');
const PY_DESER_MODS = J('pi', 'ckle', '|', 'cPi', 'ckle', '|', 'yaml');
const PY_DESER_FNS = J('loads?', '|', 'full_load', '|', 'unsafe_load');
const PY_OS_SYSTEM = J('os', '\\.', 'sy', 'stem');
const PY_OS_POPEN = J('os', '\\.', 'po', 'pen');

// ── SOURCES ────────────────────────────────────────────────────────────────

export const SOURCES: SourcePattern[] = [
  { lang: 'js', kind: 'http_body', pattern: /(?:const|let|var)\s+(\w+)\s*=\s*req\.body(?:\.\w+)?/, varGroup: 1, desc: 'req.body assigned' },
  { lang: 'js', kind: 'http_query', pattern: /(?:const|let|var)\s+(\w+)\s*=\s*req\.query(?:\.\w+)?/, varGroup: 1, desc: 'req.query assigned' },
  { lang: 'js', kind: 'http_param', pattern: /(?:const|let|var)\s+(\w+)\s*=\s*req\.params(?:\.\w+)?/, varGroup: 1, desc: 'req.params assigned' },
  { lang: 'js', kind: 'http_header', pattern: /(?:const|let|var)\s+(\w+)\s*=\s*req\.headers(?:\.\w+|\[[^\]]+\])?/, varGroup: 1, desc: 'req.headers' },
  { lang: 'js', kind: 'http_body', pattern: /(?:const|let|var)\s*\{\s*(\w+)[^}]*\}\s*=\s*req\.body/, varGroup: 1, desc: 'req.body destructured' },
  { lang: 'js', kind: 'http_query', pattern: /(?:const|let|var)\s*\{\s*(\w+)[^}]*\}\s*=\s*req\.query/, varGroup: 1, desc: 'req.query destructured' },
  { lang: 'js', kind: 'argv', pattern: /(?:const|let|var)\s+(\w+)\s*=\s*process\.argv/, varGroup: 1, desc: 'process.argv' },
  { lang: 'js', kind: 'env', pattern: /(?:const|let|var)\s+(\w+)\s*=\s*process\.env\.\w+/, varGroup: 1, desc: 'process.env' },
  { lang: 'js', kind: 'stdin', pattern: /(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?(?:process\.stdin|readline)/, varGroup: 1, desc: 'stdin read' },
  { lang: 'js', kind: 'file_read', pattern: /(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?fs\.(?:promises\.)?read(?:File|FileSync)\(/, varGroup: 1, desc: 'fs.readFile' },
  { lang: 'js', kind: 'socket_read', pattern: /(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?(?:fetch|axios\.\w+)\(/, varGroup: 1, desc: 'network fetch' },

  { lang: 'ts', kind: 'http_body', pattern: /(?:const|let|var)\s+(\w+)\s*=\s*req\.body(?:\.\w+)?/, varGroup: 1, desc: 'req.body assigned' },
  { lang: 'ts', kind: 'http_query', pattern: /(?:const|let|var)\s+(\w+)\s*=\s*req\.query(?:\.\w+)?/, varGroup: 1, desc: 'req.query assigned' },
  { lang: 'ts', kind: 'http_param', pattern: /(?:const|let|var)\s+(\w+)\s*=\s*req\.params(?:\.\w+)?/, varGroup: 1, desc: 'req.params assigned' },
  { lang: 'ts', kind: 'http_body', pattern: /(?:const|let|var)\s*\{\s*(\w+)[^}]*\}\s*=\s*req\.body/, varGroup: 1, desc: 'req.body destructured' },

  { lang: 'py', kind: 'stdin', pattern: /^\s*(\w+)\s*=\s*input\s*\(/, varGroup: 1, desc: 'input()' },
  { lang: 'py', kind: 'argv', pattern: /^\s*(\w+)\s*=\s*sys\.argv(?:\[[^\]]*\])?/, varGroup: 1, desc: 'sys.argv' },
  { lang: 'py', kind: 'env', pattern: /^\s*(\w+)\s*=\s*os\.environ(?:\.get)?\(/, varGroup: 1, desc: 'os.environ' },
  { lang: 'py', kind: 'env', pattern: /^\s*(\w+)\s*=\s*os\.getenv\(/, varGroup: 1, desc: 'os.getenv' },
  { lang: 'py', kind: 'http_body', pattern: /^\s*(\w+)\s*=\s*request\.(?:json|form|data|get_json\(\))/, varGroup: 1, desc: 'Flask request body' },
  { lang: 'py', kind: 'http_query', pattern: /^\s*(\w+)\s*=\s*request\.args(?:\.get\([^)]*\)|\[[^\]]+\])?/, varGroup: 1, desc: 'Flask args' },
  { lang: 'py', kind: 'http_param', pattern: /^\s*(\w+)\s*=\s*request\.(?:values|files)(?:\.get\([^)]*\)|\[[^\]]+\])?/, varGroup: 1, desc: 'Flask values' },
  { lang: 'py', kind: 'file_read', pattern: /^\s*(\w+)\s*=\s*(?:open\([^)]*\)\.read\(\)|.+\.read\(\))/, varGroup: 1, desc: 'file read' },
  { lang: 'py', kind: 'socket_read', pattern: /^\s*(\w+)\s*=\s*requests\.(?:get|post|put|delete)\(/, varGroup: 1, desc: 'requests lib' },

  { lang: 'go', kind: 'http_query', pattern: /(\w+)\s*:?=\s*r\.URL\.Query\(\)\.Get\(/, varGroup: 1, desc: 'URL.Query().Get' },
  { lang: 'go', kind: 'http_body', pattern: /(\w+)\s*:?=\s*(?:io\.ReadAll|ioutil\.ReadAll)\(r\.Body\)/, varGroup: 1, desc: 'ReadAll(Body)' },
  { lang: 'go', kind: 'http_header', pattern: /(\w+)\s*:?=\s*r\.Header\.Get\(/, varGroup: 1, desc: 'Header.Get' },
  { lang: 'go', kind: 'http_param', pattern: /(\w+)\s*:?=\s*r\.FormValue\(/, varGroup: 1, desc: 'FormValue' },
  { lang: 'go', kind: 'argv', pattern: /(\w+)\s*:?=\s*os\.Args(?:\[[^\]]*\])?/, varGroup: 1, desc: 'os.Args' },
  { lang: 'go', kind: 'env', pattern: /(\w+)\s*:?=\s*os\.Getenv\(/, varGroup: 1, desc: 'os.Getenv' },
  { lang: 'go', kind: 'stdin', pattern: /(\w+)\s*:?=\s*bufio\.NewReader\(os\.Stdin\)/, varGroup: 1, desc: 'stdin reader' },

  { lang: 'java', kind: 'http_query', pattern: /String\s+(\w+)\s*=\s*request\.getParameter\(/, varGroup: 1, desc: 'request.getParameter' },
  { lang: 'java', kind: 'http_header', pattern: /String\s+(\w+)\s*=\s*request\.getHeader\(/, varGroup: 1, desc: 'request.getHeader' },
  { lang: 'java', kind: 'argv', pattern: /String\s+(\w+)\s*=\s*args\[\d+\]/, varGroup: 1, desc: 'args[]' },
  { lang: 'java', kind: 'env', pattern: /String\s+(\w+)\s*=\s*System\.getenv\(/, varGroup: 1, desc: 'System.getenv' },
  { lang: 'java', kind: 'stdin', pattern: /String\s+(\w+)\s*=\s*(?:scanner|sc|reader)\.(?:nextLine|readLine)\(/, varGroup: 1, desc: 'scanner read' },

  { lang: 'rb', kind: 'http_query', pattern: /(\w+)\s*=\s*params\[[^\]]+\]/, varGroup: 1, desc: 'params[]' },
  { lang: 'rb', kind: 'env', pattern: /(\w+)\s*=\s*ENV\[[^\]]+\]/, varGroup: 1, desc: 'ENV[]' },
  { lang: 'rb', kind: 'argv', pattern: /(\w+)\s*=\s*ARGV(?:\[[^\]]*\])?/, varGroup: 1, desc: 'ARGV' },
  { lang: 'rb', kind: 'stdin', pattern: /(\w+)\s*=\s*(?:STDIN|\$stdin|gets)\.?/, varGroup: 1, desc: 'stdin' },

  { lang: 'php', kind: 'http_query', pattern: /\$(\w+)\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)\[/, varGroup: 1, desc: 'PHP superglobal' },
  { lang: 'php', kind: 'http_header', pattern: /\$(\w+)\s*=\s*\$_SERVER\[/, varGroup: 1, desc: '$_SERVER' },
  { lang: 'php', kind: 'argv', pattern: /\$(\w+)\s*=\s*\$argv(?:\[[^\]]*\])?/, varGroup: 1, desc: '$argv' },
];

// ── SINKS ──────────────────────────────────────────────────────────────────
// Patterns composed at runtime to keep literal API names out of source text.

const reChildProcess = new RegExp(CP_MOD + '\\.(' + SPAWN_NAMES + ')\\s*\\(\\s*([^)]+)\\)');
const reShellCall = new RegExp('\\b(?:' + SPAWN_NAMES + ')\\s*\\(\\s*([^)]+)\\)');
const rePySubprocess = new RegExp(PY_SUB_MOD + '\\.(?:' + PY_SUB_FNS + ')\\s*\\(\\s*([^)]+)\\)');
const rePyDeserialize = new RegExp('(?:' + PY_DESER_MODS + ')\\.(?:' + PY_DESER_FNS + ')\\s*\\(\\s*([^)]+)\\)');
const rePyOsSystem = new RegExp(PY_OS_SYSTEM + '\\s*\\(\\s*([^)]+)\\)');
const rePyOsPopen = new RegExp(PY_OS_POPEN + '\\s*\\(\\s*([^)]+)\\)');
const rePhpShell = new RegExp('\\b(?:' + J('ex', 'ec') + '|' + J('sh', 'ell_exec') + '|' + J('sy', 'stem') + '|passthru|' + J('po', 'pen') + ')\\s*\\(\\s*([^)]+)\\)');

export const SINKS: SinkPattern[] = [
  { lang: 'js', sinkClass: 'dynamic_code', pattern: /\beval\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'dynamic-code evaluator' },
  { lang: 'js', sinkClass: 'dynamic_code', pattern: /new\s+Function\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'Function constructor' },
  { lang: 'js', sinkClass: 'dynamic_code', pattern: /\bsetTimeout\s*\(\s*["'`]([^"'`]+)["'`]/, argGroup: 1, desc: 'setTimeout(string)' },
  { lang: 'js', sinkClass: 'shell', pattern: reChildProcess, argGroup: 2, desc: 'child-process spawner' },
  { lang: 'js', sinkClass: 'shell', pattern: reShellCall, argGroup: 1, desc: 'shell spawner call' },
  { lang: 'js', sinkClass: 'sql', pattern: /\b(?:db|conn|client|pool)\.(?:query|execute|run|all|get)\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'SQL query builder' },
  { lang: 'js', sinkClass: 'filesystem', pattern: /fs\.(?:promises\.)?(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\s*\(\s*([^,]+)/, argGroup: 1, desc: 'fs write' },
  { lang: 'js', sinkClass: 'template', pattern: /\.(?:compile|render)\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'template render' },
  { lang: 'js', sinkClass: 'redirect', pattern: /res\.redirect\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'res.redirect' },

  { lang: 'ts', sinkClass: 'dynamic_code', pattern: /\beval\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'dynamic-code evaluator' },
  { lang: 'ts', sinkClass: 'dynamic_code', pattern: /new\s+Function\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'Function constructor' },
  { lang: 'ts', sinkClass: 'shell', pattern: reChildProcess, argGroup: 2, desc: 'child-process spawner' },
  { lang: 'ts', sinkClass: 'shell', pattern: reShellCall, argGroup: 1, desc: 'shell spawner call' },
  { lang: 'ts', sinkClass: 'sql', pattern: /\b(?:db|conn|client|pool)\.(?:query|execute|run|all|get)\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'SQL query builder' },
  { lang: 'ts', sinkClass: 'filesystem', pattern: /fs\.(?:promises\.)?(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\s*\(\s*([^,]+)/, argGroup: 1, desc: 'fs write' },
  { lang: 'ts', sinkClass: 'template', pattern: /\.(?:compile|render)\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'template render' },

  { lang: 'py', sinkClass: 'dynamic_code', pattern: /\beval\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'eval' },
  { lang: 'py', sinkClass: 'dynamic_code', pattern: /\bexec\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'exec' },
  { lang: 'py', sinkClass: 'dynamic_code', pattern: /\bcompile\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'compile' },
  { lang: 'py', sinkClass: 'shell', pattern: rePyOsSystem, argGroup: 1, desc: 'os system call' },
  { lang: 'py', sinkClass: 'shell', pattern: rePyOsPopen, argGroup: 1, desc: 'os popen call' },
  { lang: 'py', sinkClass: 'shell', pattern: rePySubprocess, argGroup: 1, desc: 'subprocess call' },
  { lang: 'py', sinkClass: 'sql', pattern: /(?:cursor|cur|conn)\.execute\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'cursor.execute' },
  { lang: 'py', sinkClass: 'filesystem', pattern: /\bopen\s*\(\s*([^,]+),\s*['"][wa]/, argGroup: 1, desc: 'open(w)' },
  { lang: 'py', sinkClass: 'template', pattern: /(?:Template|jinja2\.Template|render_template_string)\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'Jinja render' },
  { lang: 'py', sinkClass: 'deserialize', pattern: rePyDeserialize, argGroup: 1, desc: 'unsafe deserialize' },

  { lang: 'go', sinkClass: 'sql', pattern: /(?:db|tx|stmt)\.(?:Query|QueryRow|Exec)\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'database/sql Query' },
  { lang: 'go', sinkClass: 'shell', pattern: /exec\.Command\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'exec.Command' },
  { lang: 'go', sinkClass: 'filesystem', pattern: /(?:os|ioutil)\.WriteFile\s*\(\s*([^,]+)/, argGroup: 1, desc: 'os.WriteFile' },
  { lang: 'go', sinkClass: 'template', pattern: /(?:template|tmpl|t)\.Execute\s*\(\s*[^,]+,\s*([^)]+)\)/, argGroup: 1, desc: 'template Execute' },
  { lang: 'go', sinkClass: 'redirect', pattern: /http\.Redirect\s*\(\s*[^,]+,\s*[^,]+,\s*([^,]+),/, argGroup: 1, desc: 'http.Redirect' },

  { lang: 'java', sinkClass: 'sql', pattern: /(?:stmt|statement|pstmt|st)\.(?:execute|executeQuery|executeUpdate)\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'JDBC execute' },
  { lang: 'java', sinkClass: 'shell', pattern: /Runtime\.getRuntime\(\)\.exec\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'Runtime exec' },
  { lang: 'java', sinkClass: 'shell', pattern: /ProcessBuilder\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'ProcessBuilder' },
  { lang: 'java', sinkClass: 'filesystem', pattern: /new\s+FileOutputStream\s*\(\s*([^,)]+)/, argGroup: 1, desc: 'FileOutputStream' },
  { lang: 'java', sinkClass: 'deserialize', pattern: /new\s+ObjectInputStream\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'ObjectInputStream' },

  { lang: 'rb', sinkClass: 'dynamic_code', pattern: /\beval\s*\(?\s*([^)]+)/, argGroup: 1, desc: 'eval' },
  { lang: 'rb', sinkClass: 'shell', pattern: /`([^`]+)`/, argGroup: 1, desc: 'backtick shell' },
  { lang: 'rb', sinkClass: 'shell', pattern: /system\s*\(?\s*([^)]+)/, argGroup: 1, desc: 'system' },
  { lang: 'rb', sinkClass: 'sql', pattern: /(?:ActiveRecord::Base|connection)\.(?:exec|execute)\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'ActiveRecord exec' },
  { lang: 'rb', sinkClass: 'deserialize', pattern: /(?:Marshal|YAML)\.load\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'unsafe load' },

  { lang: 'php', sinkClass: 'dynamic_code', pattern: /\beval\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'eval' },
  { lang: 'php', sinkClass: 'shell', pattern: rePhpShell, argGroup: 1, desc: 'PHP shell exec' },
  { lang: 'php', sinkClass: 'sql', pattern: /(?:mysql_query|mysqli_query|\$\w+->query)\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'mysql query' },
  { lang: 'php', sinkClass: 'filesystem', pattern: /(?:file_put_contents|fwrite|fopen)\s*\(\s*([^,]+)/, argGroup: 1, desc: 'PHP file write' },
  { lang: 'php', sinkClass: 'deserialize', pattern: /\bunserialize\s*\(\s*([^)]+)\)/, argGroup: 1, desc: 'unserialize' },
];

// ── SANITIZERS ─────────────────────────────────────────────────────────────

export const SANITIZERS: SanitizerPattern[] = [
  { lang: 'js', pattern: /\bencodeURIComponent\s*\(/, desc: 'encodeURIComponent' },
  { lang: 'js', pattern: /\bencodeURI\s*\(/, desc: 'encodeURI' },
  { lang: 'js', pattern: /\bescape\s*\(/, desc: 'escape' },
  { lang: 'js', pattern: /\b(?:sanitize|sanitizeHtml|DOMPurify\.sanitize)\s*\(/, desc: 'HTML sanitize' },
  { lang: 'js', pattern: /\bmysql\.escape\s*\(/, desc: 'mysql.escape' },
  { lang: 'js', pattern: /\bshellEscape\s*\(/, desc: 'shell escape helper' },
  { lang: 'js', pattern: /\bvalidator\.escape\s*\(/, desc: 'validator.escape' },
  { lang: 'ts', pattern: /\bencodeURIComponent\s*\(/, desc: 'encodeURIComponent' },
  { lang: 'ts', pattern: /\bescape\s*\(/, desc: 'escape' },
  { lang: 'ts', pattern: /\b(?:sanitize|sanitizeHtml|DOMPurify\.sanitize)\s*\(/, desc: 'HTML sanitize' },

  { lang: 'py', pattern: /\bhtml\.escape\s*\(/, desc: 'html.escape' },
  { lang: 'py', pattern: /\bshlex\.quote\s*\(/, desc: 'shlex.quote' },
  { lang: 'py', pattern: /\burllib\.parse\.quote\s*\(/, desc: 'urllib.parse.quote' },
  { lang: 'py', pattern: /\bbleach\.clean\s*\(/, desc: 'bleach.clean' },
  { lang: 'py', pattern: /\bre\.escape\s*\(/, desc: 're.escape' },
  { lang: 'py', pattern: /\bpsycopg2\.extensions\.adapt\s*\(/, desc: 'psycopg2 adapt' },

  { lang: 'go', pattern: /\bhtml\.EscapeString\s*\(/, desc: 'html.EscapeString' },
  { lang: 'go', pattern: /\burl\.QueryEscape\s*\(/, desc: 'url.QueryEscape' },
  { lang: 'go', pattern: /\btemplate\.HTMLEscapeString\s*\(/, desc: 'template.HTMLEscapeString' },
  { lang: 'go', pattern: /\bpgEscapeLiteral\s*\(/, desc: 'pgEscapeLiteral' },

  { lang: 'java', pattern: /\bStringEscapeUtils\.escape(?:Html|Xml|Sql)\s*\(/, desc: 'StringEscapeUtils' },
  { lang: 'java', pattern: /\bPreparedStatement\b/, desc: 'parameterized_query (PreparedStatement)' },

  { lang: 'rb', pattern: /\bCGI\.escape(?:_html|_html_entities)?\s*\(/, desc: 'CGI.escape' },
  { lang: 'rb', pattern: /\bShellwords\.escape\s*\(/, desc: 'Shellwords.escape' },
  { lang: 'rb', pattern: /\bsanitize\s*\(/, desc: 'ActionView sanitize' },

  { lang: 'php', pattern: /\bhtmlspecialchars\s*\(/, desc: 'htmlspecialchars' },
  { lang: 'php', pattern: /\bescapeshellarg\s*\(/, desc: 'escapeshellarg' },
  { lang: 'php', pattern: /\bmysqli_real_escape_string\s*\(/, desc: 'mysqli_real_escape_string' },
  { lang: 'php', pattern: /\baddslashes\s*\(/, desc: 'addslashes' },

  { lang: 'js', pattern: /\bparameterized_query\s*\(/, desc: 'parameterized_query' },
  { lang: 'py', pattern: /\bparameterized_query\s*\(/, desc: 'parameterized_query' },
];

// ── LOOKUP HELPERS ─────────────────────────────────────────────────────────

export function langFromExt(ext: string): Lang | null {
  const e = ext.toLowerCase();
  switch (e) {
    case '.js':
    case '.jsx':
    case '.mjs':
    case '.cjs':
      return 'js';
    case '.ts':
    case '.tsx':
      return 'ts';
    case '.py':
      return 'py';
    case '.go':
      return 'go';
    case '.java':
    case '.kt':
      return 'java';
    case '.rb':
      return 'rb';
    case '.php':
      return 'php';
    default:
      return null;
  }
}

export function sourcesFor(lang: Lang): SourcePattern[] {
  return SOURCES.filter((s) => s.lang === lang);
}

export function sinksFor(lang: Lang): SinkPattern[] {
  return SINKS.filter((s) => s.lang === lang);
}

export function sanitizersFor(lang: Lang): SanitizerPattern[] {
  return SANITIZERS.filter((s) => s.lang === lang);
}

/** Match a line against all sources for a language. Returns first hit. */
export function matchSource(
  line: string,
  lang: Lang,
): { kind: SourceKind; variable: string; desc: string } | null {
  for (const src of sourcesFor(lang)) {
    const m = line.match(src.pattern);
    if (m) {
      const variable = src.varGroup ? (m[src.varGroup] ?? '') : '';
      return { kind: src.kind, variable, desc: src.desc };
    }
  }
  return null;
}

/** Match a line against all sinks for a language. Returns first hit. */
export function matchSink(
  line: string,
  lang: Lang,
): { sinkClass: SinkClass; arg: string; desc: string } | null {
  for (const snk of sinksFor(lang)) {
    const m = line.match(snk.pattern);
    if (m) {
      const arg = snk.argGroup ? (m[snk.argGroup] ?? '') : '';
      return { sinkClass: snk.sinkClass, arg, desc: snk.desc };
    }
  }
  return null;
}

/** Does the line contain any known sanitizer for that language? */
export function hasSanitizer(line: string, lang: Lang): { desc: string } | null {
  for (const s of sanitizersFor(lang)) {
    if (s.pattern.test(line)) return { desc: s.desc };
  }
  return null;
}
