/**
 * Packet Capture Executor - wraps tcpdump (capture) + tshark (parsing).
 * Falls back to tshark -w if tcpdump is not available (useful on Windows).
 */
import cp from 'child_process';
import { promisify } from 'util';
import { promises as fs } from 'fs';
import path from 'path';
import { createCapture, updateCapture } from '../../../db.js';
import type { RuntimeJobExecutor, JobContext, CaptureConfig } from '../types.js';

const runCmd = promisify(cp.execFile);

async function which(cmd: string): Promise<string | null> {
  const candidates = process.platform === 'win32'
    ? [`${cmd}.exe`, `C:\Program Files\Wireshark\${cmd}.exe`, `C:\Program Files (x86)\Wireshark\${cmd}.exe`]
    : [cmd, `/usr/sbin/${cmd}`, `/usr/bin/${cmd}`];
  for (const cand of candidates) {
    try {
      await runCmd(cand, ['--version'], { timeout: 2000 });
      return cand;
    } catch { /* try next */ }
  }
  return null;
}

export class PcapExecutor implements RuntimeJobExecutor {
  readonly type = 'capture' as const;
  readonly tool = 'tcpdump';

  validate(config: Record<string, any>): void {
    const cfg = config as CaptureConfig;
    if (!cfg.interface || typeof cfg.interface !== 'string') {
      throw new Error('interface is required (e.g. "eth0", "any", or "lo")');
    }
  }

  async execute(ctx: JobContext): Promise<void> {
    const cfg = ctx.config as CaptureConfig;
    const pcapPath = path.join(ctx.outputDir, 'capture.pcap');

    // Create capture DB row
    const captureId = createCapture({
      job_id: ctx.jobId,
      pcap_path: pcapPath,
      filter: cfg.filter,
      start_time: new Date().toISOString(),
    });

    // Find a capture tool
    let binary = await which('tcpdump');
    let useWindump = false;
    if (!binary) {
      binary = await which('tshark');
      useWindump = true;
    }
    if (!binary) {
      throw new Error('Neither tcpdump nor tshark is available on PATH. Install Wireshark or libpcap tools.');
    }

    const args: string[] = [];
    if (useWindump) {
      // tshark syntax
      args.push('-i', cfg.interface);
      args.push('-w', pcapPath);
      if (cfg.max_packets) args.push('-c', String(cfg.max_packets));
      if (cfg.duration) args.push('-a', `duration:${cfg.duration}`);
      if (cfg.filter) args.push('-f', cfg.filter);
    } else {
      // tcpdump syntax
      args.push('-i', cfg.interface);
      args.push('-w', pcapPath);
      args.push('-U'); // unbuffered
      if (cfg.max_packets) args.push('-c', String(cfg.max_packets));
      if (!cfg.promiscuous) args.push('-p');
      if (cfg.filter) args.push(cfg.filter);
    }

    ctx.emit({ type: 'start', data: { binary, interface: cfg.interface, filter: cfg.filter } });

    const child = cp.spawn(binary, args, { stdio: ['ignore', 'pipe', 'pipe'] });

    const startTime = Date.now();
    const logPath = path.join(ctx.outputDir, 'output.log');
    const logFd = await fs.open(logPath, 'a');

    child.stderr?.on('data', (chunk: Buffer) => {
      logFd.write(chunk.toString('utf-8'));
    });

    // Periodic stats update
    const statsInterval = setInterval(async () => {
      try {
        const stat = await fs.stat(pcapPath);
        const elapsed = Math.round((Date.now() - startTime) / 1000);
        ctx.updateStats({
          bytes: stat.size,
          elapsed_seconds: elapsed,
        });
      } catch { /* file may not exist yet */ }

      // Check cancel
      if (ctx.shouldStop() && !child.killed) {
        child.kill('SIGTERM');
      }

      // Check duration
      if (cfg.duration && (Date.now() - startTime) / 1000 > cfg.duration) {
        if (!child.killed) child.kill('SIGTERM');
      }
    }, 1000);

    await new Promise<void>((resolve) => {
      child.on('exit', () => {
        clearInterval(statsInterval);
        logFd.close().catch(() => {});
        resolve();
      });
      child.on('error', (err) => {
        clearInterval(statsInterval);
        logFd.close().catch(() => {});
        console.warn(`[pcap] capture error: ${err.message}`);
        resolve();
      });
    });

    // Parse final packet count with tshark
    let packetCount = 0;
    let finalBytes = 0;
    try {
      const stat = await fs.stat(pcapPath);
      finalBytes = stat.size;

      const tsharkPath = await which('tshark');
      if (tsharkPath && finalBytes > 0) {
        const res = await runCmd(tsharkPath, ['-r', pcapPath, '-q', '-z', 'io,stat,0'], { timeout: 15000, maxBuffer: 4 * 1024 * 1024 });
        const m = res.stdout.match(/Packets:\s+(\d+)/);
        if (m) packetCount = parseInt(m[1]);
      }
    } catch (err: any) {
      console.warn(`[pcap] stats extraction failed: ${err.message}`);
    }

    updateCapture(captureId, {
      packet_count: packetCount,
      bytes: finalBytes,
      end_time: new Date().toISOString(),
    });

    ctx.updateStats({
      packet_count: packetCount,
      bytes: finalBytes,
    });

    ctx.emit({ type: 'complete', data: { pcap_path: pcapPath, packet_count: packetCount, bytes: finalBytes } });
  }
}
