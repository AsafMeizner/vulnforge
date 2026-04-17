// Server-Side Template Injection (SSTI) detection.
//
// Scope: flag sinks that compile / render a template string whose contents
// can be attacker-controlled. The distinguishing feature of SSTI vs. stored
// XSS is that the *template source itself* — not just template variables —
// is built from untrusted input. E.g. `render_template_string(user_input)`
// in Flask/Jinja2, or `Handlebars.compile(unsafe_str)` in Node.
//
// Template-engine coverage:
//   - Jinja2              (Python / Flask / Django Jinja2Backend)
//   - Handlebars          (Node)
//   - Mustache            (Node, various ports)
//   - Velocity            (Java)
//   - Freemarker          (Java)
//   - Twig                (PHP)
//   - ERB                 (Ruby)
//   - Razor/ViewEngine    (.NET)
//
// We also flag *literal* template strings that embed raw untrusted
// interpolations when the enclosing function reads user input — because
// those are the classic "escape fails" scenario.

import { findFilesByExt, readFileText, enumerateLines, isCommentLine, snippet, relPath, findingId, looksTainted, TAINTED_SOURCE_RE } from './helpers.js';
import type { InjectionFinding, SourceConfidence } from './types.js';

// Exts we scan for SSTI. Template files (.j2, .hbs, etc.) are inspected
// separately since untrusted interpolation is a different pattern there.
const CODE_EXTS = ['.py', '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs', '.rb', '.php', '.java', '.kt', '.cs', '.go'];
const TEMPLATE_EXTS = ['.j2', '.jinja', '.jinja2', '.hbs', '.handlebars', '.mustache', '.vm', '.ftl', '.twig', '.erb', '.cshtml', '.razor'];

// Sinks that compile/render a *string* as a template. These are the
// danger zone — if the string argument is tainted, it's SSTI by
// definition (the attacker controls the template).
interface SsitSinkDef {
  name: string;
  pattern: RegExp;
  engine: string;
  cwe: string;
  severity: InjectionFinding['severity'];
  /** A per-sink short description for the finding body. */
  description: string;
}

const STRING_TEMPLATE_SINKS: SsitSinkDef[] = [
  {
    name: 'flask.render_template_string',
    pattern: /\brender_template_string\s*\(/,
    engine: 'Jinja2 (Flask)',
    cwe: 'CWE-94',
    severity: 'Critical',
    description: 'Flask render_template_string compiles its first argument as a Jinja2 template. If that argument is attacker-controlled, the attacker gets Python code execution via Jinja2 sandbox escapes.',
  },
  {
    name: 'jinja2.Template',
    pattern: /\bjinja2\.Template\s*\(|\bfrom\s+jinja2\s+import[^\n]*\bTemplate\b[\s\S]{0,200}?Template\s*\(/,
    engine: 'Jinja2',
    cwe: 'CWE-94',
    severity: 'Critical',
    description: 'Constructing jinja2.Template from an untrusted string allows SSTI leading to RCE.',
  },
  {
    name: 'jinja2.Environment.from_string',
    pattern: /\bEnvironment\s*\([^)]*\)\s*\.\s*from_string\s*\(|\.\s*from_string\s*\(/,
    engine: 'Jinja2',
    cwe: 'CWE-94',
    severity: 'High',
    description: 'Jinja2 Environment.from_string compiles a string as a template; attacker-controlled input enables SSTI.',
  },
  {
    name: 'django.Template',
    pattern: /\bdjango\.template\.Template\s*\(|\bfrom\s+django\.template[\s\S]{0,200}?\bTemplate\s*\(/,
    engine: 'Django',
    cwe: 'CWE-94',
    severity: 'High',
    description: 'Django Template constructor compiles untrusted strings — SSTI exposure when input is user-controlled.',
  },
  {
    name: 'Handlebars.compile',
    pattern: /\bHandlebars\s*\.\s*compile\s*\(|\bhandlebars\s*\.\s*compile\s*\(/,
    engine: 'Handlebars',
    cwe: 'CWE-1336',
    severity: 'High',
    description: 'Handlebars.compile on an untrusted template string allows template injection and, with helpers registered, RCE-like impact.',
  },
  {
    name: 'Handlebars.precompile',
    pattern: /\bHandlebars\s*\.\s*precompile\s*\(/,
    engine: 'Handlebars',
    cwe: 'CWE-1336',
    severity: 'High',
    description: 'Handlebars.precompile on an untrusted string compiles it as a template; SSTI exposure.',
  },
  {
    name: 'Mustache.render',
    pattern: /\bMustache\s*\.\s*render\s*\(/,
    engine: 'Mustache',
    cwe: 'CWE-1336',
    severity: 'Medium',
    description: 'Mustache.render with an attacker-controlled template string allows template injection; lower severity because Mustache is logic-less, but unescaped sections can still leak data.',
  },
  {
    name: 'Velocity.Engine.evaluate',
    pattern: /\bVelocity(?:Engine)?\s*\.\s*evaluate\s*\(|\bve\.evaluate\s*\(/,
    engine: 'Velocity',
    cwe: 'CWE-94',
    severity: 'Critical',
    description: 'Velocity evaluate() executes a template string; attacker-controlled input gives Java code execution via gadget chains.',
  },
  {
    name: 'Freemarker.Template',
    pattern: /new\s+freemarker\.template\.Template\s*\(|new\s+Template\s*\([^)]*new\s+StringReader\s*\(/,
    engine: 'Freemarker',
    cwe: 'CWE-94',
    severity: 'Critical',
    description: 'Instantiating a Freemarker Template from a user-controlled string enables SSTI; Freemarker exposes freemarker.template.utility.Execute for RCE.',
  },
  {
    name: 'Twig.createTemplate',
    pattern: /->\s*createTemplate\s*\(|Twig\\Environment[\s\S]{0,100}?->\s*createTemplate\s*\(/,
    engine: 'Twig',
    cwe: 'CWE-94',
    severity: 'High',
    description: 'Twig Environment::createTemplate compiles an untrusted string; SSTI can lead to RCE via filter abuse.',
  },
  {
    name: 'ERB.new',
    pattern: /\bERB\s*\.\s*new\s*\(/,
    engine: 'ERB (Ruby)',
    cwe: 'CWE-94',
    severity: 'Critical',
    description: 'Ruby ERB.new on an untrusted string executes embedded Ruby — direct code execution.',
  },
  {
    name: 'Razor.Parse',
    pattern: /\bRazor\s*\.\s*Parse\s*\(|RazorEngine\.Engine\.Razor\.RunCompile\s*\(/,
    engine: 'Razor (.NET)',
    cwe: 'CWE-94',
    severity: 'Critical',
    description: 'RazorEngine compiles C# code embedded in a template string; untrusted input yields .NET RCE.',
  },
  {
    name: 'Jade.compile',
    pattern: /\bpug\s*\.\s*compile\s*\(|\bjade\s*\.\s*compile\s*\(/,
    engine: 'Pug/Jade',
    cwe: 'CWE-94',
    severity: 'High',
    description: 'Pug/Jade compile on an untrusted template string allows SSTI; Pug allows embedded JS expressions.',
  },
  {
    name: 'EJS.render',
    pattern: /\bejs\s*\.\s*render\s*\(|\bejs\s*\.\s*compile\s*\(/,
    engine: 'EJS',
    cwe: 'CWE-94',
    severity: 'High',
    description: 'EJS render/compile evaluates JS inside the template; attacker-controlled template gives Node.js RCE.',
  },
];

// Patterns that reveal an unescaped / raw interpolation *inside* a
// template file literal. We treat these as informational on their own,
// but they become "likely" when co-located with a tainted source in
// the same file / function.
const UNESCAPED_INTERP_PATTERNS: Array<{ engine: string; pattern: RegExp; evidence: string }> = [
  { engine: 'Handlebars', pattern: /\{\{\{\s*[\w.]+\s*\}\}\}/, evidence: '{{{ raw }}} unescaped output' },
  { engine: 'Mustache', pattern: /\{\{&\s*[\w.]+\s*\}\}/, evidence: '{{& raw }} unescaped output' },
  { engine: 'Velocity', pattern: /\$!\{\s*[\w.]+\s*\}/, evidence: '$!{ silent raw } output' },
  { engine: 'Freemarker', pattern: /\$\{\s*[\w.]+\s*\}/, evidence: '${ raw } interpolation (ensure ?html applied)' },
  { engine: 'Jinja2', pattern: /\{%\s*autoescape\s+false\s*%\}/, evidence: 'Jinja2 autoescape disabled block' },
];

// Known "safe" markers — if present near a sink, downgrade or drop.
const SAFE_MARKERS = [
  /\bescape\s*\(/,
  /\bSafeString\s*\(/,
  /\bhtml\.escape\s*\(/,
  /\bmarkupsafe\.escape\s*\(/,
  /\bbleach\.clean\s*\(/,
  /\bsanitize\s*\(/,
];

/**
 * Return true if a whitelist of "definitely safe constant input" can be
 * inferred — e.g. a string literal passed directly with no concatenation.
 * This lets us skip the classic `render_template_string("hello")` case
 * which is not an SSTI bug.
 */
function isSinkArgLiteral(line: string, afterSink: string): boolean {
  // A literal string argument: matches "..." or '...' or `...` with
  // only whitespace / comma / closing paren after. No `+`, no variable.
  const m = afterSink.match(/^\s*(?:'[^']*'|"[^"]*"|`[^`]*`|r?'''[\s\S]*?'''|r?"""[\s\S]*?""")\s*[\),]/);
  if (!m) return false;
  // Reject if the line also has a `+` or `%s` interpolation near the sink.
  if (/[+%]\s*\w/.test(afterSink.slice(0, 80))) return false;
  return true;
}

function sourceConfidenceFor(sinkLine: string, contextLines: string[]): SourceConfidence {
  if (looksTainted(sinkLine)) return 'definite';
  // If any of the N lines in the surrounding context references a
  // tainted source, bump to "likely".
  for (const l of contextLines) if (looksTainted(l)) return 'likely';
  return 'possible';
}

function contextAround(lines: string[], idx: number, span = 6): string[] {
  const start = Math.max(0, idx - span);
  const end = Math.min(lines.length, idx + span + 1);
  return lines.slice(start, end);
}

/**
 * Scan code files for SSTI sinks. Emits one finding per (file, line, sink)
 * combination. Deduplication across detectors is the orchestrator's job.
 */
export function detectSsti(projectPath: string, maxFiles = 4000): InjectionFinding[] {
  const out: InjectionFinding[] = [];
  const files = findFilesByExt(projectPath, [...CODE_EXTS, ...TEMPLATE_EXTS]).slice(0, maxFiles);

  for (const file of files) {
    const text = readFileText(file);
    if (text == null) continue;
    const ext = file.slice(file.lastIndexOf('.')).toLowerCase();
    const rel = relPath(projectPath, file);
    const lines = text.split(/\r?\n/);

    // --- code sinks -------------------------------------------------
    if (CODE_EXTS.includes(ext)) {
      for (const [lineNo, raw] of enumerateLines(text)) {
        if (isCommentLine(raw)) continue;
        for (const sink of STRING_TEMPLATE_SINKS) {
          const m = raw.match(sink.pattern);
          if (!m) continue;

          // Skip if the first arg is clearly a literal string.
          const afterSink = raw.slice(m.index! + m[0].length);
          if (isSinkArgLiteral(raw, afterSink)) continue;

          // Skip if a safe-marker is on the same line as a wrapper.
          if (SAFE_MARKERS.some((rx) => rx.test(raw))) continue;

          const ctx = contextAround(lines, lineNo - 1);
          const sc = sourceConfidenceFor(raw, ctx);

          // Drop purely "possible" findings when the surrounding scope
          // shows no http/server setup — reduces noise on template
          // demo/config files.
          if (sc === 'possible' && !/\b(app|router|route|controller|view|handler|serve)\b/i.test(ctx.join('\n'))) {
            continue;
          }

          const severity: InjectionFinding['severity'] =
            sc === 'definite' ? sink.severity
              : sink.severity === 'Critical' ? 'High'
                : sink.severity === 'High' ? 'Medium'
                  : sink.severity;

          out.push({
            category: 'injection',
            subcategory: 'ssti',
            title: `SSTI: ${sink.engine} sink ${sink.name} on untrusted input`,
            severity,
            file: rel,
            line_start: lineNo,
            sink_type: sink.name,
            source_confidence: sc,
            cwe: sink.cwe,
            evidence: snippet(raw),
            confidence: sc === 'definite' ? 'high' : sc === 'likely' ? 'medium' : 'low',
            description: sink.description,
            id: findingId('ssti', rel, lineNo, sink.name),
          });
        }
      }
    }

    // --- template-file interpolations (informational unless paired) ----
    if (TEMPLATE_EXTS.includes(ext)) {
      // Only flag if the project has *any* indication of user input flowing
      // to template rendering. We can't cheaply check the global AST here,
      // so we emit Low severity with source_confidence='possible' — the
      // integrator can suppress these via severity thresholds.
      for (const [lineNo, raw] of enumerateLines(text)) {
        for (const p of UNESCAPED_INTERP_PATTERNS) {
          if (p.pattern.test(raw)) {
            out.push({
              category: 'injection',
              subcategory: 'ssti',
              title: `SSTI: unescaped ${p.engine} interpolation in template`,
              severity: 'Low',
              file: rel,
              line_start: lineNo,
              sink_type: `template.${p.engine.toLowerCase()}.unescaped`,
              source_confidence: 'possible',
              cwe: 'CWE-79',
              evidence: `${p.evidence}: ${snippet(raw)}`,
              confidence: 'low',
              description: `Template contains an unescaped output construct. If any render context value is user-controlled, this is an SSTI/XSS sink. Verify the controller that supplies the context.`,
              id: findingId('ssti', rel, lineNo, p.engine + ':unescaped'),
            });
            break;
          }
        }
      }
    }
  }

  return out;
}

// Exposed for tests — re-export the sink list so coverage tests can
// verify engines we claim to cover.
export const SSTI_SINKS = STRING_TEMPLATE_SINKS;
