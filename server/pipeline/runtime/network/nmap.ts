/**
 * Nmap Executor - port/service scanning with XML output parsing.
 */
import cp from 'child_process';
import { promisify } from 'util';
import { promises as fs } from 'fs';
import path from 'path';
import type { RuntimeJobExecutor, JobContext, PortScanConfig, PortScanResult } from '../types.js';

const runCmd = promisify(cp.execFile);

async function findNmap(): Promise<string | null> {
  const candidates = process.platform === 'win32'
    ? ['nmap.exe', 'C:\Program Files (x86)\Nmap\nmap.exe', 'C:\Program Files\Nmap\nmap.exe']
    : ['nmap', '/usr/bin/nmap', '/usr/local/bin/nmap'];
  for (const cand of candidates) {
    try {
      await runCmd(cand, ['--version'], { timeout: 2000 });
      return cand;
    } catch { /* try next */ }
  }
  return null;
}

export class NmapExecutor implements RuntimeJobExecutor {
  readonly type = 'portscan' as const;
  readonly tool = 'nmap';

  validate(config: Record<string, any>): void {
    const cfg = config as PortScanConfig;
    if (!cfg.target || typeof cfg.target !== 'string') {
      throw new Error('target is required (IP, hostname, CIDR, or range)');
    }
  }

  async execute(ctx: JobContext): Promise<void> {
    const cfg = ctx.config as PortScanConfig;
    const xmlPath = path.join(ctx.outputDir, 'nmap.xml');

    const binary = await findNmap();
    if (!binary) {
      throw new Error('nmap is not available on PATH. Install from https://nmap.org/');
    }

    const args: string[] = ['-oX', xmlPath];

    // Scan type
    switch (cfg.scan_type) {
      case 'syn': args.push('-sS'); break;
      case 'connect': args.push('-sT'); break;
      case 'udp': args.push('-sU'); break;
      case 'version': args.push('-sV'); break;
      case 'script': args.push('-sC'); break;
      default: args.push('-sT'); // connect scan is safest (no root required)
    }

    // Ports
    if (cfg.ports) {
      args.push('-p', cfg.ports);
    }

    // Scripts
    if (cfg.scripts && Array.isArray(cfg.scripts) && cfg.scripts.length > 0) {
      args.push(`--script=${cfg.scripts.join(',')}`);
    }

    // Timing (T0-T5)
    const timing = typeof cfg.timing === 'number' ? cfg.timing : 3;
    args.push(`-T${Math.max(0, Math.min(5, timing))}`);

    // Target last
    args.push(cfg.target);

    ctx.emit({ type: 'start', data: { binary, args } });

    const timeout = (cfg.timeout || 300) * 1000;
    const logPath = path.join(ctx.outputDir, 'output.log');

    try {
      const res = await runCmd(binary, args, { timeout, maxBuffer: 32 * 1024 * 1024 });
      await fs.writeFile(logPath, res.stdout + '\n' + res.stderr);
    } catch (err: any) {
      const out = (err.stdout || '') + '\n' + (err.stderr || '');
      await fs.writeFile(logPath, out);
      if (!err.stdout && !err.stderr) {
        throw new Error(`nmap failed: ${err.message}`);
      }
    }

    if (ctx.shouldStop()) {
      throw new Error('Port scan cancelled');
    }

    // Parse XML output
    let xml = '';
    try {
      xml = await fs.readFile(xmlPath, 'utf-8');
    } catch {
      throw new Error('nmap XML output not found - scan may have failed');
    }

    const result = this.parseNmapXml(xml);

    ctx.updateStats(result.summary);
    ctx.emit({ type: 'output', data: { result } });
  }

  private parseNmapXml(xml: string): PortScanResult {
    const hosts: PortScanResult['hosts'] = [];

    // Each <host>...</host> block
    const hostBlocks = xml.match(/<host[\s\S]*?<\/host>/g) || [];

    for (const hostBlock of hostBlocks) {
      // Address
      const addrMatch = hostBlock.match(/<address\s+addr="([^"]+)"\s+addrtype="(ipv4|ipv6)"/);
      const address = addrMatch ? addrMatch[1] : '';

      // Hostname
      const hostMatch = hostBlock.match(/<hostname\s+name="([^"]+)"/);
      const hostname = hostMatch ? hostMatch[1] : undefined;

      // Status
      const statusMatch = hostBlock.match(/<status\s+state="([^"]+)"/);
      const state = statusMatch ? statusMatch[1] : 'unknown';

      // Ports
      const ports: PortScanResult['hosts'][0]['ports'] = [];
      const portBlocks = hostBlock.match(/<port[\s\S]*?<\/port>/g) || [];

      for (const portBlock of portBlocks) {
        const portIdMatch = portBlock.match(/portid="(\d+)"/);
        const protocolMatch = portBlock.match(/protocol="([^"]+)"/);
        const portStateMatch = portBlock.match(/<state\s+state="([^"]+)"/);
        const serviceMatch = portBlock.match(/<service\s+name="([^"]+)"(?:\s+product="([^"]+)")?(?:\s+version="([^"]+)")?/);

        if (portIdMatch && protocolMatch) {
          ports.push({
            port: parseInt(portIdMatch[1]),
            protocol: protocolMatch[1],
            state: portStateMatch?.[1] || 'unknown',
            service: serviceMatch?.[1],
            version: serviceMatch?.[3] || serviceMatch?.[2],
          });
        }
      }

      if (address) {
        hosts.push({ address, hostname, state, ports });
      }
    }

    const totalHosts = hosts.length;
    const upHosts = hosts.filter(h => h.state === 'up').length;
    const totalPorts = hosts.reduce((n, h) => n + h.ports.length, 0);
    const openPorts = hosts.reduce(
      (n, h) => n + h.ports.filter(p => p.state === 'open').length,
      0
    );

    return {
      hosts,
      summary: {
        total_hosts: totalHosts,
        up_hosts: upHosts,
        total_ports: totalPorts,
        open_ports: openPorts,
      },
    };
  }
}
