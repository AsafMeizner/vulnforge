/**
 * Simple template-based libFuzzer harness generator.
 * Parses a function signature and produces a harness skeleton.
 */

export interface HarnessResult {
  harness_code: string;
  notes: string[];
}

/** Quick-and-dirty C/C++ parameter parser. Splits on commas, trims each. */
function parseParams(params: string): string[] {
  const trimmed = params.trim();
  if (!trimmed || trimmed === 'void') return [];
  const result: string[] = [];
  let depth = 0;
  let buf = '';
  for (const ch of trimmed) {
    if (ch === '(' || ch === '<') depth++;
    if (ch === ')' || ch === '>') depth--;
    if (ch === ',' && depth === 0) {
      result.push(buf.trim());
      buf = '';
    } else {
      buf += ch;
    }
  }
  if (buf.trim()) result.push(buf.trim());
  return result;
}

/** Detect if a parameter looks like a pointer (ends with * or [ or const *). */
function isPointer(param: string): boolean {
  return /\*|\[/.test(param);
}

/** Detect if a parameter looks like a size/length field. */
function isSizeType(param: string): boolean {
  return /\b(size_t|ssize_t|uint32_t|uint64_t|int32_t|int64_t|int|long|unsigned|size|len|length|count)\b/i.test(param);
}

/** Extract the bare parameter name (last identifier). */
function getParamName(param: string): string {
  const m = param.match(/(\w+)\s*\[?\]?\s*$/);
  return m ? m[1] : 'arg';
}

export function generateHarness(signature: string, language = 'c'): HarnessResult {
  const notes: string[] = [];
  const lang = language.toLowerCase();

  if (lang !== 'c' && lang !== 'cpp' && lang !== 'c++') {
    notes.push(`Language "${language}" is not yet fully supported - returning a stub. Only C/C++ are auto-generated today.`);
    return {
      harness_code: `// TODO: libFuzzer harness for ${language} is not supported yet.\n// Manual harness required. See https://llvm.org/docs/LibFuzzer.html\n`,
      notes,
    };
  }

  // Parse the signature: "returntype funcname(params)"
  const sigMatch = signature.match(/^\s*(?:(?:static|extern|inline|const)\s+)*([\w*\s]+?)\s+(\w+)\s*\(([^)]*)\)/);

  if (!sigMatch) {
    notes.push('Could not parse signature - ensure it matches "returntype funcname(params)" format.');
    return {
      harness_code: `// TODO: Could not parse signature: ${signature}\n// Please write the harness manually.\n`,
      notes,
    };
  }

  const [, returnType, funcName, paramStr] = sigMatch;
  const params = parseParams(paramStr);

  // Detect data/length pair: pointer param followed by size param
  let dataParamIdx = -1;
  let sizeParamIdx = -1;
  for (let i = 0; i < params.length; i++) {
    if (isPointer(params[i]) && i + 1 < params.length && isSizeType(params[i + 1])) {
      dataParamIdx = i;
      sizeParamIdx = i + 1;
      break;
    }
  }

  const header = [
    '#include <stdint.h>',
    '#include <stddef.h>',
    '#include <stdlib.h>',
    '#include <string.h>',
    '',
    '// Declaration of the target function under test.',
    `extern ${returnType.trim()} ${funcName}(${paramStr.trim()});`,
    '',
    'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {',
  ];

  const body: string[] = [];

  if (dataParamIdx >= 0 && params.length === 2) {
    // Simple case: parse_packet(uint8_t *data, size_t len)
    notes.push('Detected data/length pair - generated direct call.');
    body.push(`    ${funcName}((${params[dataParamIdx].replace(/\w+\s*$/, '').trim()})Data, (${params[sizeParamIdx].replace(/\w+\s*$/, '').trim()})Size);`);
  } else if (params.length === 1 && isPointer(params[0])) {
    // Single null-terminated string
    notes.push('Single pointer arg detected - treating as NUL-terminated. Note: input is not guaranteed to end with NUL.');
    body.push('    // TODO: libFuzzer inputs are not NUL-terminated. Copy into a buffer if needed.');
    body.push('    char *buf = (char*)malloc(Size + 1);');
    body.push('    if (!buf) return 0;');
    body.push('    memcpy(buf, Data, Size);');
    body.push('    buf[Size] = 0;');
    body.push(`    ${funcName}(buf);`);
    body.push('    free(buf);');
  } else if (params.length === 0) {
    notes.push('Function takes no arguments - harness will call it repeatedly with no fuzz input. Consider whether this is what you want.');
    body.push(`    ${funcName}();`);
    body.push('    (void)Data; (void)Size;');
  } else {
    // Complex signature: stub with TODOs
    notes.push(`Complex signature with ${params.length} params - generated a stub. You\'ll need to unpack Data into the expected inputs.`);
    body.push('    // TODO: This function has a non-trivial signature:');
    body.push(`    //   ${signature.trim()}`);
    body.push('    // Unpack Data into the expected inputs. Typical patterns:');
    body.push('    //   - Split Data into sub-buffers with known offsets');
    body.push('    //   - Treat Data as a struct via memcpy() (beware alignment!)');
    body.push('    //   - Use FuzzedDataProvider (see libFuzzer docs)');
    body.push('    (void)Data; (void)Size;');
  }

  const footer = ['    return 0;', '}', ''];

  return {
    harness_code: [...header, ...body, ...footer].join('\n'),
    notes,
  };
}
