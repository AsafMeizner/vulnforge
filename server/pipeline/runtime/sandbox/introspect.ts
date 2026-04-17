/**
 * Sandbox introspection helpers - shared between Docker and QEMU executors.
 * All functions spawn CLI tools via execFile (no shell injection).
 */
import cp from 'child_process';
import { promisify } from 'util';
import { promises as fs } from 'fs';
import path from 'path';
import net from 'net';

const runCmd = promisify(cp.execFile);

// ── Docker helpers ─────────────────────────────────────────────────────────

/** Check if Docker daemon is accessible. */
export async function dockerAvailable(): Promise<boolean> {
  try {
    await runCmd('docker', ['info'], { timeout: 5000 });
    return true;
  } catch { return false; }
}

/** Get live resource stats for a container. */
export async function dockerStats(containerId: string): Promise<{
  cpu_percent: number;
  memory_mb: number;
  memory_limit_mb: number;
  network_rx_bytes: number;
  network_tx_bytes: number;
}> {
  const { stdout } = await runCmd('docker', [
    'stats', '--no-stream', '--format',
    '{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}',
    containerId,
  ], { timeout: 10000 });

  const parts = stdout.trim().split('|');
  const cpu = parseFloat((parts[0] || '0').replace('%', '')) || 0;

  // Parse "123.4MiB / 512MiB"
  const memParts = (parts[1] || '0 / 0').split('/');
  const memUsed = parseSizeToMB(memParts[0]?.trim() || '0');
  const memLimit = parseSizeToMB(memParts[1]?.trim() || '0');

  // Parse "1.23kB / 4.56kB"
  const netParts = (parts[2] || '0 / 0').split('/');
  const rx = parseSizeToBytes(netParts[0]?.trim() || '0');
  const tx = parseSizeToBytes(netParts[1]?.trim() || '0');

  return { cpu_percent: cpu, memory_mb: memUsed, memory_limit_mb: memLimit, network_rx_bytes: rx, network_tx_bytes: tx };
}

/** List processes running inside a container. */
export async function dockerTop(containerId: string): Promise<Array<{ pid: string; user: string; command: string }>> {
  try {
    const { stdout } = await runCmd('docker', ['top', containerId], { timeout: 5000 });
    const lines = stdout.trim().split('\n');
    if (lines.length < 2) return [];
    // First line is headers, rest are processes
    return lines.slice(1).map(line => {
      const cols = line.split(/\s+/);
      return { user: cols[0] || '', pid: cols[1] || '', command: cols.slice(7).join(' ') || cols.slice(2).join(' ') };
    });
  } catch { return []; }
}

/** Get container status. */
export async function dockerInspectStatus(containerId: string): Promise<string> {
  try {
    const { stdout } = await runCmd('docker', [
      'inspect', '--format', '{{.State.Status}}', containerId,
    ], { timeout: 5000 });
    return stdout.trim();
  } catch { return 'unknown'; }
}

/** Pause a Docker container. */
export async function dockerPause(containerId: string): Promise<void> {
  await runCmd('docker', ['pause', containerId], { timeout: 10000 });
}

/** Unpause a Docker container. */
export async function dockerUnpause(containerId: string): Promise<void> {
  await runCmd('docker', ['unpause', containerId], { timeout: 10000 });
}

/** Create a snapshot (docker commit). */
export async function dockerSnapshot(containerId: string, name: string): Promise<string> {
  const tag = `vulnforge-snapshot:${name}`;
  await runCmd('docker', ['commit', containerId, tag], { timeout: 60000 });
  return tag;
}

/** Copy a file into a container. */
export async function dockerCopyIn(containerId: string, hostPath: string, containerPath: string): Promise<void> {
  await runCmd('docker', ['cp', hostPath, `${containerId}:${containerPath}`], { timeout: 30000 });
}

/** Copy a file out of a container. */
export async function dockerCopyOut(containerId: string, containerPath: string, hostPath: string): Promise<void> {
  await runCmd('docker', ['cp', `${containerId}:${containerPath}`, hostPath], { timeout: 30000 });
}

// ── Size parsing ───────────────────────────────────────────────────────────

function parseSizeToMB(s: string): number {
  const num = parseFloat(s);
  if (isNaN(num)) return 0;
  if (/gib/i.test(s)) return num * 1024;
  if (/mib/i.test(s)) return num;
  if (/kib/i.test(s)) return num / 1024;
  if (/gb/i.test(s)) return num * 1000;
  if (/mb/i.test(s)) return num;
  if (/kb/i.test(s)) return num / 1000;
  return num;
}

function parseSizeToBytes(s: string): number {
  const num = parseFloat(s);
  if (isNaN(num)) return 0;
  if (/gb/i.test(s)) return num * 1e9;
  if (/mb/i.test(s)) return num * 1e6;
  if (/kb/i.test(s)) return num * 1e3;
  if (/b$/i.test(s)) return num;
  return num;
}

// ── Port allocation ────────────────────────────────────────────────────────

/** Find a free TCP port in range. */
export async function findFreePort(start = 10000, end = 20000): Promise<number> {
  for (let port = start; port <= end; port++) {
    const free = await isPortFree(port);
    if (free) return port;
  }
  throw new Error(`No free port found in range ${start}-${end}`);
}

function isPortFree(port: number): Promise<boolean> {
  return new Promise(resolve => {
    const server = net.createServer();
    server.once('error', () => resolve(false));
    server.once('listening', () => { server.close(() => resolve(true)); });
    server.listen(port, '127.0.0.1');
  });
}
