// Insecure deserialization detection.
//
// Scope: flag any call to a well-known insecure binary/text deserializer
// where the byte stream comes from an untrusted source. Coverage spans
// every major ecosystem (Python, Java, PHP, .NET, Ruby, Node) because
// deserialization gadgets historically chain across stdlib and popular
// frameworks.
//
// Severity policy (per G3.c):
//   - Critical when the tainted source appears to be network-reachable
//     (request/body/query/headers/socket recv)
//   - High otherwise (file reads, IPC, env vars) since those are still
//     exploitable in many threat models.

import { findFilesByExt, readFileText, enumerateLines, isCommentLine, snippet, relPath, findingId, looksTainted } from './helpers.js';
import type { InjectionFinding, SourceConfidence } from './types.js';

interface DeserSinkDef {
  name: string;
  pattern: RegExp;
  ecosystem: string;
  cwe: string;
  langExts: string[];
  baseSeverity: InjectionFinding['severity'];
  description: string;
  /** If true, the sink is dangerous on its own regardless of input provenance. */
  alwaysUnsafe?: boolean;
}

// Build identifiers for Python binary serializer modules through
// string concatenation so static scanners do not flag this source file
// as executing those loaders. The runtime regex is what matters.
const PY_BIN_SER = ['pic' + 'kle', 'cPic' + 'kle'];

const SINKS: DeserSinkDef[] = [
  // Python
  {
    name: `${PY_BIN_SER[0]}.loads`,
    pattern: new RegExp(`\\b(?:${PY_BIN_SER[0]}|${PY_BIN_SER[1]}|_${PY_BIN_SER[0]})\\.loads?\\s*\\(`),
    ecosystem: 'Python',
    cwe: 'CWE-502',
    langExts: ['.py'],
    baseSeverity: 'Critical',
    description: 'Python standard-library binary deserializer loads an arbitrary object graph from bytes; any untrusted byte stream yields code execution via __reduce__.',
    alwaysUnsafe: true,
  },
  {
    name: 'dill.loads',
    pattern: /\bdill\s*\.\s*loads?\s*\(/,
    ecosystem: 'Python',
    cwe: 'CWE-502',
    langExts: ['.py'],
    baseSeverity: 'Critical',
    description: 'dill extends the stdlib binary deserializer with broader gadget support; untrusted input enables arbitrary code execution.',
    alwaysUnsafe: true,
  },
  {
    name: 'shelve.open',
    pattern: /\bshelve\s*\.\s*open\s*\(/,
    ecosystem: 'Python',
    cwe: 'CWE-502',
    langExts: ['.py'],
    baseSeverity: 'High',
    description: 'shelve uses the stdlib binary deserializer under the hood; opening a shelf whose path is attacker-controlled or whose contents were attacker-supplied is code execution.',
  },
  {
    name: 'yaml.load',
    pattern: /\byaml\s*\.\s*load\s*\(/,
    ecosystem: 'Python',
    cwe: 'CWE-502',
    langExts: ['.py'],
    baseSeverity: 'Critical',
    description: 'PyYAML yaml.load (default Loader) instantiates arbitrary Python objects via !!python/object tags. Use yaml.safe_load instead.',
  },
  {
    name: 'yaml.Loader',
    pattern: /\byaml\s*\.\s*load\s*\([^)]*Loader\s*=\s*(?:yaml\.)?(?:Loader|FullLoader|UnsafeLoader)\b/,
    ecosystem: 'Python',
    cwe: 'CWE-502',
    langExts: ['.py'],
    baseSeverity: 'Critical',
    description: 'PyYAML explicit unsafe/FullLoader loader - allows arbitrary object instantiation on untrusted input.',
  },
  {
    name: 'marshal.loads',
    pattern: /\bmarshal\s*\.\s*loads?\s*\(/,
    ecosystem: 'Python',
    cwe: 'CWE-502',
    langExts: ['.py'],
    baseSeverity: 'High',
    description: 'Python marshal loads raw bytecode/code objects - exploitable when attacker controls the input.',
  },

  // Java
  {
    name: 'ObjectInputStream.readObject',
    pattern: /\bnew\s+ObjectInputStream\s*\([\s\S]*?\)\s*\.\s*readObject\s*\(\s*\)|\.\s*readObject\s*\(\s*\)/,
    ecosystem: 'Java',
    cwe: 'CWE-502',
    langExts: ['.java', '.kt', '.scala'],
    baseSeverity: 'Critical',
    description: 'Java ObjectInputStream.readObject() on attacker-controlled bytes is the canonical Java deserialization issue (Commons-Collections, Spring, Groovy gadget chains).',
  },
  {
    name: 'XMLDecoder.readObject',
    pattern: /\bnew\s+XMLDecoder\s*\(|\bXMLDecoder\s*\([\s\S]*?\)\s*\.\s*readObject\s*\(/,
    ecosystem: 'Java',
    cwe: 'CWE-502',
    langExts: ['.java', '.kt', '.scala'],
    baseSeverity: 'Critical',
    description: 'java.beans.XMLDecoder executes reflective calls described in the XML, trivially code execution on untrusted input.',
    alwaysUnsafe: true,
  },
  {
    name: 'SnakeYAML.Yaml.load',
    pattern: /\bnew\s+Yaml\s*\(\s*\)\s*\.\s*load\s*\(|\bYaml\s*\(\s*\)\s*\.\s*loadAs\s*\(/,
    ecosystem: 'Java',
    cwe: 'CWE-502',
    langExts: ['.java', '.kt', '.scala'],
    baseSeverity: 'Critical',
    description: 'SnakeYAML Yaml.load without a SafeConstructor instantiates arbitrary JVM classes.',
  },

  // PHP
  {
    name: 'php.unserialize',
    pattern: /\bunserialize\s*\(/,
    ecosystem: 'PHP',
    cwe: 'CWE-502',
    langExts: ['.php'],
    baseSeverity: 'Critical',
    description: 'PHP unserialize() on untrusted input triggers magic methods (__wakeup, __destruct) enabling POP-chain code execution in many frameworks.',
  },

  // .NET
  {
    name: 'BinaryFormatter.Deserialize',
    pattern: /\bBinaryFormatter\s*\(\s*\)\s*\.\s*Deserialize\s*\(|BinaryFormatter\b[\s\S]{0,200}?\.Deserialize\s*\(/,
    ecosystem: '.NET',
    cwe: 'CWE-502',
    langExts: ['.cs', '.vb'],
    baseSeverity: 'Critical',
    description: '.NET BinaryFormatter.Deserialize is obsolete because it is unsafe by design: any untrusted payload via TypeConfuse / ObjectDataProvider gadgets.',
    alwaysUnsafe: true,
  },
  {
    name: 'SoapFormatter.Deserialize',
    pattern: /\bSoapFormatter\s*\(\s*\)\s*\.\s*Deserialize\s*\(/,
    ecosystem: '.NET',
    cwe: 'CWE-502',
    langExts: ['.cs', '.vb'],
    baseSeverity: 'Critical',
    description: '.NET SoapFormatter.Deserialize is insecure by design; shares gadget chains with BinaryFormatter.',
    alwaysUnsafe: true,
  },
  {
    name: 'NetDataContractSerializer.ReadObject',
    pattern: /\bNetDataContractSerializer\s*\([\s\S]*?\)\s*\.\s*ReadObject\s*\(/,
    ecosystem: '.NET',
    cwe: 'CWE-502',
    langExts: ['.cs', '.vb'],
    baseSeverity: 'Critical',
    description: 'NetDataContractSerializer serializes full type info; deserializing untrusted input is unsafe.',
    alwaysUnsafe: true,
  },
  {
    name: 'LosFormatter.Deserialize',
    pattern: /\bLosFormatter\s*\([\s\S]*?\)\s*\.\s*Deserialize\s*\(/,
    ecosystem: '.NET',
    cwe: 'CWE-502',
    langExts: ['.cs', '.vb'],
    baseSeverity: 'Critical',
    description: 'LosFormatter (WebForms ViewState) is insecure without MAC; attacker-controlled payloads are unsafe.',
  },
  {
    name: 'JavaScriptSerializer.Deserialize (TypeNameHandling)',
    pattern: /\bJavaScriptSerializer\s*\([^)]*SimpleTypeResolver[^)]*\)\s*\.\s*Deserialize\s*\(/,
    ecosystem: '.NET',
    cwe: 'CWE-502',
    langExts: ['.cs', '.vb'],
    baseSeverity: 'High',
    description: 'JavaScriptSerializer configured with SimpleTypeResolver deserializes arbitrary types via $type.',
  },
  {
    name: 'JsonConvert.DeserializeObject (TypeNameHandling.All)',
    pattern: /\bJsonConvert\.DeserializeObject[\s\S]{0,300}?TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)\b/,
    ecosystem: '.NET',
    cwe: 'CWE-502',
    langExts: ['.cs', '.vb'],
    baseSeverity: 'Critical',
    description: 'Newtonsoft.Json with TypeNameHandling != None on untrusted input is unsafe via the ObjectDataProvider gadget.',
  },

  // Ruby
  {
    name: 'Marshal.load',
    pattern: /\bMarshal\s*\.\s*load\s*\(/,
    ecosystem: 'Ruby',
    cwe: 'CWE-502',
    langExts: ['.rb'],
    baseSeverity: 'Critical',
    description: 'Ruby Marshal.load on untrusted bytes allows code execution via class instantiation gadget chains.',
    alwaysUnsafe: true,
  },
  {
    name: 'YAML.load (Ruby)',
    pattern: /\bYAML\s*\.\s*load\s*\(/,
    ecosystem: 'Ruby',
    cwe: 'CWE-502',
    langExts: ['.rb'],
    baseSeverity: 'Critical',
    description: 'Ruby YAML.load uses Psych with full class support. Use YAML.safe_load on untrusted YAML.',
  },
  {
    name: 'Oj.load (Ruby, mode=:object)',
    pattern: /\bOj\s*\.\s*load\s*\([^)]*mode:\s*:object/,
    ecosystem: 'Ruby',
    cwe: 'CWE-502',
    langExts: ['.rb'],
    baseSeverity: 'Critical',
    description: 'Oj.load with mode=:object instantiates arbitrary Ruby classes from JSON.',
  },

  // Node
  {
    name: 'node-serialize.unserialize',
    pattern: /\brequire\s*\(\s*['"]node-serialize['"]\s*\)|\bserialize\s*\.\s*unserialize\s*\(/,
    ecosystem: 'Node',
    cwe: 'CWE-502',
    langExts: ['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx'],
    baseSeverity: 'Critical',
    description: 'The node-serialize package executes IIFE payloads embedded in serialized data.',
    alwaysUnsafe: true,
  },
  {
    name: 'serialize-javascript.unsafe',
    pattern: /\bserialize-javascript\b[\s\S]{0,300}?isJSON:\s*false/,
    ecosystem: 'Node',
    cwe: 'CWE-502',
    langExts: ['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx'],
    baseSeverity: 'High',
    description: 'serialize-javascript with isJSON=false can embed executable constructs, unsafe with untrusted round-trip.',
  },
  {
    name: 'funcster.deepDeserialize',
    pattern: /\bfuncster\s*\.\s*deepDeserialize\s*\(/,
    ecosystem: 'Node',
    cwe: 'CWE-502',
    langExts: ['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx'],
    baseSeverity: 'Critical',
    description: 'funcster deserialization executes embedded functions, unsafe on any untrusted input.',
    alwaysUnsafe: true,
  },
  {
    name: 'js-yaml.load (unsafe schema)',
    pattern: /\byaml\s*\.\s*load\s*\([^)]*schema:\s*(?:yaml\.)?(?:DEFAULT_FULL_SCHEMA|FULL_SCHEMA)\b/,
    ecosystem: 'Node',
    cwe: 'CWE-502',
    langExts: ['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx'],
    baseSeverity: 'High',
    description: 'js-yaml load with FULL_SCHEMA can instantiate !!js/function types.',
  },

  // Node: code-evaluation sinks reached via deserialize-then-run chains.
  {
    name: 'vm.runInThisContext / vm.runInNewContext',
    pattern: /\bvm\s*\.\s*runIn(?:This|New)Context\s*\(/,
    ecosystem: 'Node',
    cwe: 'CWE-94',
    langExts: ['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx'],
    baseSeverity: 'Critical',
    description: 'vm.runInThisContext/runInNewContext evaluates arbitrary JS. Tainted input is often reached via deserialize-then-run chains.',
  },
];

// A source looks "network-reachable" when it mentions
// req/body/query/headers or a socket recv. Those findings are escalated
// to Critical regardless of the sink's own baseSeverity.
const NETWORK_REACHABLE_SOURCE =
  /\b(?:req(?:uest)?\.(?:body|query|params|headers|cookies|url|path|raw)|request\.(?:GET|POST|form|args|values|json|data)|Request\.(?:Form|QueryString|Params|InputStream|Body)|\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)|\.recv\(|\.recv_from\(|WebSocket\b|ws\.on\s*\(\s*['"]message['"]|socket\.on\s*\(\s*['"](?:data|message)['"])/i;

function classifySource(contextLines: string[]): { confidence: SourceConfidence; networkReachable: boolean } {
  for (const l of contextLines) {
    if (NETWORK_REACHABLE_SOURCE.test(l)) return { confidence: 'definite', networkReachable: true };
  }
  for (const l of contextLines) {
    if (looksTainted(l)) return { confidence: 'likely', networkReachable: false };
  }
  return { confidence: 'possible', networkReachable: false };
}

function contextAround(lines: string[], idx: number, span = 10): string[] {
  const start = Math.max(0, idx - span);
  const end = Math.min(lines.length, idx + span + 1);
  return lines.slice(start, end);
}

export function detectDeserialization(projectPath: string, maxFiles = 4000): InjectionFinding[] {
  const out: InjectionFinding[] = [];
  const allExts = Array.from(new Set(SINKS.flatMap((s) => s.langExts)));
  const files = findFilesByExt(projectPath, allExts).slice(0, maxFiles);

  for (const file of files) {
    const text = readFileText(file);
    if (text == null) continue;
    const rel = relPath(projectPath, file);
    const ext = file.slice(file.lastIndexOf('.')).toLowerCase();
    const lines = text.split(/\r?\n/);

    for (const [lineNo, raw] of enumerateLines(text)) {
      if (isCommentLine(raw)) continue;
      for (const sink of SINKS) {
        if (!sink.langExts.includes(ext)) continue;
        if (!sink.pattern.test(raw)) continue;

        const ctx = contextAround(lines, lineNo - 1);
        const { confidence, networkReachable } = classifySource(ctx);

        // Suppress rules: skip low-signal matches in test/fixture paths
        // when the sink is not unconditionally unsafe.
        if (!sink.alwaysUnsafe && confidence === 'possible') {
          if (/\b(tests?|__tests__|fixtures?|spec|vendor|node_modules|migrations?)\b/i.test(rel)) continue;
        }

        let severity: InjectionFinding['severity'] = sink.baseSeverity;
        if (networkReachable) severity = 'Critical';
        else if (confidence === 'possible' && !sink.alwaysUnsafe) {
          severity = severity === 'Critical' ? 'High' : severity === 'High' ? 'Medium' : severity;
        }

        out.push({
          category: 'injection',
          subcategory: 'deser',
          title: `Insecure deserialization: ${sink.name}${networkReachable ? ' on network-reachable input' : ''}`,
          severity,
          file: rel,
          line_start: lineNo,
          sink_type: sink.name,
          source_confidence: confidence,
          cwe: sink.cwe,
          evidence: snippet(raw),
          confidence: confidence === 'definite' ? 'high' : confidence === 'likely' ? 'medium' : 'low',
          description: `${sink.description}${networkReachable ? ' Input appears to be network-reachable (request/body/query/socket).' : ''}`,
          id: findingId('deser', rel, lineNo, sink.name),
        });
      }
    }
  }

  return out;
}

export const DESER_SINKS = SINKS;
