/**
 * Crash triage helpers — stack hash computation and exploitability classification.
 */
import crypto from 'crypto';

/** Strip addresses and line numbers from a stack frame line for normalization. */
export function normalizeStackFrame(line: string): string {
  return line
    .replace(/0x[0-9a-fA-F]+/g, '')   // addresses
    .replace(/:\d+/g, '')              // line numbers
    .replace(/\s+/g, ' ')              // collapse whitespace
    .trim();
}

/**
 * Compute a stable hash of a stack trace by taking the first 5 frame function
 * names. Used to deduplicate crashes that share a root cause.
 */
export function computeStackHash(stackTrace: string): string {
  const lines = stackTrace.split('\n');
  const frames: string[] = [];

  for (const line of lines) {
    // Match common stack frame patterns:
    //   #N 0xADDR in FUNCTION at FILE:LINE
    //   #N 0xADDR in FUNCTION
    //   #N FUNCTION at FILE:LINE       (libFuzzer/ASan without address)
    //   at FUNCTION(...)                (simplified)
    let match = line.match(/#\d+\s+(?:0x[0-9a-fA-F]+\s+)?in\s+([^\s(]+)/);
    if (!match) {
      match = line.match(/#\d+\s+([^\s(]+)/);
    }
    if (!match) {
      match = line.match(/^\s*at\s+([^\s(]+)/);
    }
    if (match) {
      const fn = match[1].trim();
      // Skip obvious libFuzzer/ASan internal frames
      if (/^(__asan|__sanitizer|fuzzer::|LLVMFuzzer)/i.test(fn)) continue;
      frames.push(fn);
      if (frames.length >= 5) break;
    }
  }

  if (frames.length === 0) {
    // Fall back to hashing the whole trace (normalized)
    return crypto.createHash('md5').update(normalizeStackFrame(stackTrace)).digest('hex').slice(0, 16);
  }

  return crypto.createHash('md5').update(frames.join('|')).digest('hex').slice(0, 16);
}

/**
 * Simple heuristic exploitability classification.
 * Inspired by Microsoft's !exploitable and CERT Triage Tools.
 */
export function classifyExploitability(crash: { signal?: string; stack_trace?: string }): 'high' | 'medium' | 'low' | 'unknown' {
  const sig = (crash.signal || '').toUpperCase();
  const trace = (crash.stack_trace || '').toLowerCase();

  // High: write to invalid memory, heap corruption, stack overflow
  if (/\bheap[- ]buffer[- ]overflow\s+write/i.test(trace)) return 'high';
  if (/\bstack[- ]buffer[- ]overflow\s+write/i.test(trace)) return 'high';
  if (/\bwrite of size/i.test(trace)) return 'high';
  if (/\buse[- ]after[- ]free\s+write/i.test(trace)) return 'high';
  if (/double[- ]free|bad[- ]free/i.test(trace)) return 'high';
  if (sig === 'SIGSEGV' && /\bwrite\b/i.test(trace)) return 'high';

  // Medium: reads from invalid memory, aborts
  if (sig === 'SIGABRT') return 'medium';
  if (/\bheap[- ]buffer[- ]overflow\s+read/i.test(trace)) return 'medium';
  if (/\buse[- ]after[- ]free\s+read/i.test(trace)) return 'medium';
  if (/\bread of size/i.test(trace)) return 'medium';
  if (sig === 'SIGSEGV') return 'medium'; // SEGV without write context

  // Low: arithmetic, bus errors, illegal instructions
  if (sig === 'SIGFPE') return 'low';
  if (sig === 'SIGBUS') return 'low';
  if (sig === 'SIGILL') return 'low';

  return 'unknown';
}
