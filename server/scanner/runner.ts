import { spawn } from 'child_process';
import { EventEmitter } from 'events';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, unlinkSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';

// TOOLS_DIR is env-configurable. Points at the directory containing
// Python scanner .py files. Default retained for dev backward-compat.
const TOOLS_DIR = process.env.VULNFORGE_TOOLS_DIR || 'X:/security-solver/tools';

export interface RunOptions {
  language?: string;
  timeout?: number;
  extraArgs?: string[];
}

export interface RunnerEvents {
  output: (line: string) => void;
  complete: (output: string, code: number) => void;
  error: (err: Error) => void;
}

export class ToolRunner extends EventEmitter {
  private toolName: string;
  private targetPath: string;
  private options: RunOptions;
  private outputLines: string[] = [];
  private tempFile: string | null = null;

  constructor(toolName: string, targetPath: string, options: RunOptions = {}) {
    super();
    this.toolName = toolName;
    this.targetPath = targetPath;
    this.options = options;
  }

  run(): void {
    const toolPath = path.join(TOOLS_DIR, `${this.toolName}.py`);

    if (!existsSync(toolPath)) {
      this.emit('error', new Error(`Tool not found: ${toolPath}`));
      return;
    }

    // Create temp file for output
    const tmpDir = mkdtempSync(path.join(tmpdir(), 'vulnforge-'));
    this.tempFile = path.join(tmpDir, 'output.md');

    const args: string[] = [toolPath, this.targetPath, '--output', this.tempFile];

    if (this.options.language) {
      args.push('--language', this.options.language);
    }

    if (this.options.extraArgs) {
      args.push(...this.options.extraArgs);
    }

    const timeout = this.options.timeout || 300000; // 5 min default

    const child = spawn('python3', args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout,
    });

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');

    child.stdout.on('data', (chunk: string) => {
      const lines = chunk.split('\n');
      lines.forEach(line => {
        if (line.trim()) {
          this.outputLines.push(line);
          this.emit('output', line);
        }
      });
    });

    child.stderr.on('data', (chunk: string) => {
      const lines = chunk.split('\n');
      lines.forEach(line => {
        if (line.trim()) {
          const errLine = `[stderr] ${line}`;
          this.outputLines.push(errLine);
          this.emit('output', errLine);
        }
      });
    });

    child.on('close', (code: number | null) => {
      const exitCode = code ?? -1;
      let fileOutput = '';

      // Prefer the --output file content if it exists
      if (this.tempFile && existsSync(this.tempFile)) {
        try {
          fileOutput = readFileSync(this.tempFile, 'utf8');
          unlinkSync(this.tempFile);
        } catch {
          // fall through to stdout output
        }
      }

      const finalOutput = fileOutput || this.outputLines.join('\n');
      this.emit('complete', finalOutput, exitCode);
    });

    child.on('error', (err: Error) => {
      this.emit('error', err);
    });
  }
}

export async function runTool(
  toolName: string,
  targetPath: string,
  options: RunOptions = {}
): Promise<{ output: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    const runner = new ToolRunner(toolName, targetPath, options);

    runner.on('complete', (output: string, code: number) => {
      resolve({ output, exitCode: code });
    });

    runner.on('error', (err: Error) => {
      reject(err);
    });

    runner.run();
  });
}

export function streamTool(
  toolName: string,
  targetPath: string,
  options: RunOptions = {}
): ToolRunner {
  const runner = new ToolRunner(toolName, targetPath, options);
  runner.run();
  return runner;
}
