import { execFile } from 'child_process';

export interface ChatResponse {
  content: string;
  model: string;
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
  };
}

/**
 * Invokes the `claude` CLI with -p (print mode) so it reads the prompt from
 * the argument and writes the response to stdout without requiring interactive
 * input.  Requires the claude CLI to be on PATH.
 */
export async function chatClaudeCLI(prompt: string): Promise<ChatResponse> {
  return new Promise((resolve, reject) => {
    // -p = print mode (non-interactive, reads prompt from arg, writes to stdout)
    // --output-format text = plain text output (no JSON wrapper)
    execFile(
      'claude',
      ['-p', prompt, '--output-format', 'text'],
      { timeout: 120000, maxBuffer: 10 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) {
          reject(new Error(`Claude CLI error: ${err.message}${stderr ? `\n${stderr}` : ''}`));
          return;
        }
        resolve({
          content: stdout.trim(),
          model: 'claude-code',
        });
      }
    );
  });
}
