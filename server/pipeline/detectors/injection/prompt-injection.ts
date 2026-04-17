import { findFilesByExt, readFileText, enumerateLines, snippet, relPath, findingId, looksTainted } from './helpers.js';
import type { InjectionFinding } from './types.js';

/**
 * Prompt-injection detector. Flags user input flowing into LLM calls.
 */
const LLM_CALL = /(?:openai|anthropic|ollama)[\w.]*(?:create|generate|chat)\s*\(|routeAI\s*\(|\.messages\.create\s*\(|\.chat\.completions\.create\s*\(/;
const SYSTEM_PROMPT_CONCAT = /system\s*:\s*[`'"][^`'"]*\$\{[^}]+\}|system\s*:\s*[`'"][^`'"]*(?:"|')\s*\+\s*\w+/;

export function detectPromptInjection(projectPath: string, maxFiles = 4000): InjectionFinding[] {
  const files = findFilesByExt(projectPath, ['.js', '.mjs', '.cjs', '.ts', '.tsx', '.py'], maxFiles);
  const findings: InjectionFinding[] = [];
  for (const file of files) {
    const src = readFileText(file);
    if (!src) continue;
    if (!LLM_CALL.test(src)) continue;
    for (const [lineNum, line] of enumerateLines(src)) {
      if (SYSTEM_PROMPT_CONCAT.test(line) && looksTainted(line)) {
        findings.push({
          id: findingId('prompt', file, lineNum, 'llm_system_prompt'),
          category: 'injection',
          subcategory: 'prompt',
          title: 'User input concatenated into LLM system prompt',
          severity: 'High',
          file: relPath(projectPath, file),
          line_start: lineNum,
          sink_type: 'llm_system_prompt',
          source_confidence: 'likely',
          evidence: snippet(line),
          confidence: 'high',
          cwe: 'CWE-1427',
        });
        continue;
      }
      if (LLM_CALL.test(line) && /\$\{[^}]+\}|["'`]\s*\+\s*\w+/.test(line) && looksTainted(line)) {
        findings.push({
          id: findingId('prompt', file, lineNum, 'llm_user_prompt'),
          category: 'injection',
          subcategory: 'prompt',
          title: 'Possible prompt injection via unbracketed user input',
          severity: 'Medium',
          file: relPath(projectPath, file),
          line_start: lineNum,
          sink_type: 'llm_user_prompt',
          source_confidence: 'possible',
          evidence: snippet(line),
          confidence: 'low',
          cwe: 'CWE-1427',
        });
      }
    }
  }
  return findings;
}
