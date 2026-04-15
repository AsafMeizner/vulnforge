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
    execFile(
      'claude',
      ['-p', prompt, '--no-input'],
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
