import { Router, type Request, type Response } from 'express';
import { promises as fs } from 'fs';
import cp from 'child_process';
import { promisify } from 'util';
import path from 'path';
import {
  getRuntimeJobs,
  getRuntimeJobById,
  deleteRuntimeJob,
  getFuzzCrashes,
  getFuzzCrashById,
  updateFuzzCrash,
  getSandboxSnapshots,
  type RuntimeJobFilters,
} from '../db.js';

const runCmd = promisify(cp.execFile);
const router = Router();

/** Parse JSON columns so responses are structured, not strings. */
function hydrate(job: any): any {
  if (!job) return null;
  return {
    ...job,
    config: safeJson(job.config),
    stats: safeJson(job.stats),
  };
}

function safeJson(s?: string): any {
  if (!s) return {};
  try { return JSON.parse(s); } catch { return {}; }
}

// GET /api/runtime - list jobs
router.get('/', (req: Request, res: Response) => {
  try {
    const filters: RuntimeJobFilters = {};
    if (req.query.status) filters.status = String(req.query.status);
    if (req.query.type) filters.type = String(req.query.type);
    if (req.query.project_id) filters.project_id = Number(req.query.project_id);
    if (req.query.finding_id) filters.finding_id = Number(req.query.finding_id);
    if (req.query.limit) filters.limit = Number(req.query.limit);

    const rows = getRuntimeJobs(filters);
    res.json({ data: rows.map(hydrate), total: rows.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/runtime/crashes - list crashes (top-level shortcut)
router.get('/crashes', (req: Request, res: Response) => {
  try {
    const filters: { job_id?: string; linked_finding_id?: number } = {};
    if (req.query.job_id) filters.job_id = String(req.query.job_id);
    if (req.query.linked_finding_id) filters.linked_finding_id = Number(req.query.linked_finding_id);
    const crashes = getFuzzCrashes(filters);
    res.json({ data: crashes, total: crashes.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/runtime/crashes/:id/link - link a crash to a finding
router.post('/crashes/:id/link', async (req: Request, res: Response) => {
  try {
    const id = Number(String(req.params.id));
    const { finding_id } = req.body;
    if (!finding_id) { res.status(400).json({ error: 'finding_id required' }); return; }
    const crash = getFuzzCrashById(id);
    if (!crash) { res.status(404).json({ error: 'crash not found' }); return; }
    updateFuzzCrash(id, { linked_finding_id: Number(finding_id) });
    res.json(getFuzzCrashById(id));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/runtime/harness-gen - generate a libFuzzer harness
router.post('/harness-gen', async (req: Request, res: Response) => {
  try {
    const { function_signature, language } = req.body;
    if (!function_signature) { res.status(400).json({ error: 'function_signature required' }); return; }
    const { generateHarness } = await import('../pipeline/runtime/fuzzers/harness-gen.js');
    const result = generateHarness(function_signature, language || 'c');
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/runtime - start a job
router.post('/', async (req: Request, res: Response) => {
  try {
    const { type, tool, config, project_id, finding_id } = req.body;
    if (!type || !tool) { res.status(400).json({ error: 'type and tool required' }); return; }

    const { runtimeJobRunner } = await import('../pipeline/runtime/job-runner.js');
    const id = await runtimeJobRunner.start({
      type, tool, config: config || {},
      projectId: project_id ? Number(project_id) : undefined,
      findingId: finding_id ? Number(finding_id) : undefined,
    });
    res.status(202).json({ id, status: 'queued' });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

// GET /api/runtime/:id - job details
router.get('/:id', (req: Request, res: Response) => {
  try {
    const job = getRuntimeJobById(String(req.params.id));
    if (!job) { res.status(404).json({ error: 'job not found' }); return; }
    res.json(hydrate(job));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/runtime/:id/stop
router.post('/:id/stop', async (req: Request, res: Response) => {
  try {
    const { runtimeJobRunner } = await import('../pipeline/runtime/job-runner.js');
    const ok = await runtimeJobRunner.stop(String(req.params.id));
    res.json({ stopped: ok });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/runtime/:id - delete job + output dir
router.delete('/:id', async (req: Request, res: Response) => {
  try {
    const job = getRuntimeJobById(String(req.params.id));
    if (!job) { res.status(404).json({ error: 'job not found' }); return; }
    deleteRuntimeJob(String(req.params.id));
    if (job.output_dir) {
      try { await fs.rm(job.output_dir, { recursive: true, force: true }); } catch { /* ignore */ }
    }
    res.json({ deleted: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/runtime/:id/output - tail output log
router.get('/:id/output', async (req: Request, res: Response) => {
  try {
    const job = getRuntimeJobById(String(req.params.id));
    if (!job) { res.status(404).json({ error: 'job not found' }); return; }
    if (!job.output_dir) { res.status(404).json({ error: 'no output directory' }); return; }

    const logPath = path.join(job.output_dir, 'output.log');
    try {
      const content = await fs.readFile(logPath, 'utf-8');
      const tail = Math.min(Number(req.query.tail) || 100, 1000);
      const lines = content.split('\n');
      const tailed = lines.slice(-tail).join('\n');
      res.type('text/plain').send(tailed);
    } catch {
      res.type('text/plain').send('');
    }
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/runtime/:id/crashes - per-job crashes
router.get('/:id/crashes', (req: Request, res: Response) => {
  try {
    const crashes = getFuzzCrashes({ job_id: String(req.params.id) });
    res.json({ data: crashes, total: crashes.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/runtime/:id/pcap - download raw pcap
router.get('/:id/pcap', async (req: Request, res: Response) => {
  try {
    const job = getRuntimeJobById(String(req.params.id));
    if (!job?.output_dir) { res.status(404).json({ error: 'not found' }); return; }
    const pcapPath = path.join(job.output_dir, 'capture.pcap');
    await fs.access(pcapPath);
    res.download(pcapPath, `${String(req.params.id)}.pcap`);
  } catch {
    res.status(404).json({ error: 'pcap not found' });
  }
});

// GET /api/runtime/:id/packets - parse pcap with tshark
router.get('/:id/packets', async (req: Request, res: Response) => {
  try {
    const job = getRuntimeJobById(String(req.params.id));
    if (!job?.output_dir) { res.status(404).json({ error: 'not found' }); return; }
    const pcapPath = path.join(job.output_dir, 'capture.pcap');
    try { await fs.access(pcapPath); } catch { res.json({ data: [] }); return; }

    const limit = Number(req.query.limit) || 100;
    // Resolve the tshark binary in a portable order. We walk the
    // candidate list and try each until one spawns successfully, so a
    // Windows install with Wireshark in a non-standard path just needs
    // VULNFORGE_TSHARK set (or tshark on PATH).
    const tsharkCandidates: string[] = [];
    if (process.env.VULNFORGE_TSHARK) tsharkCandidates.push(process.env.VULNFORGE_TSHARK);
    tsharkCandidates.push('tshark');
    if (process.platform === 'win32') {
      tsharkCandidates.push(
        'C:\\Program Files\\Wireshark\\tshark.exe',
        'C:\\Program Files (x86)\\Wireshark\\tshark.exe',
      );
    }

    const args = ['-r', pcapPath, '-T', 'fields',
      '-e', 'frame.number', '-e', 'frame.time_relative', '-e', 'ip.src', '-e', 'ip.dst',
      '-e', '_ws.col.Protocol', '-e', 'frame.len', '-e', '_ws.col.Info',
      '-c', String(limit),
    ];
    let lastError: any = null;
    for (const bin of tsharkCandidates) {
      try {
        const result = await runCmd(bin, args, { timeout: 30000, maxBuffer: 8 * 1024 * 1024 });
        const packets = result.stdout.trim().split('\n').filter(Boolean).map(line => {
          const [num, time, src, dst, proto, len, info] = line.split('\t');
          return { number: parseInt(num), time: parseFloat(time), src, dst, protocol: proto, length: parseInt(len), info };
        });
        res.json({ data: packets, total: packets.length });
        return;
      } catch (err: any) {
        lastError = err;
        // Only retry on spawn-level ENOENT; if tshark ran but failed,
        // that's a real error and further candidates won't help.
        if (err?.code !== 'ENOENT' && !/not found/i.test(String(err?.message))) break;
      }
    }
    res.status(503).json({
      data: [],
      error: `tshark unavailable. Install Wireshark or set VULNFORGE_TSHARK. Last error: ${lastError?.message || 'unknown'}`,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── Sandbox-specific endpoints ────────────────────────────────────────────

// POST /api/runtime/:id/pause - pause a sandbox container
router.post('/:id/pause', async (req: Request, res: Response) => {
  try {
    const job = getRuntimeJobById(String(req.params.id));
    if (!job) { res.status(404).json({ error: 'job not found' }); return; }
    if (job.type !== 'sandbox') { res.status(400).json({ error: 'only sandbox jobs can be paused' }); return; }

    const { updateRuntimeJob } = await import('../db.js');
    updateRuntimeJob(String(req.params.id), { status: 'paused' });
    // The executor polling loop will detect the status change and call docker pause
    res.json({ paused: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/runtime/:id/resume - resume a paused sandbox
router.post('/:id/resume', async (req: Request, res: Response) => {
  try {
    const job = getRuntimeJobById(String(req.params.id));
    if (!job) { res.status(404).json({ error: 'job not found' }); return; }

    const { updateRuntimeJob } = await import('../db.js');
    updateRuntimeJob(String(req.params.id), { status: 'running' });
    res.json({ resumed: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/runtime/:id/snapshot - create a named snapshot
router.post('/:id/snapshot', async (req: Request, res: Response) => {
  try {
    const job = getRuntimeJobById(String(req.params.id));
    if (!job || job.type !== 'sandbox') { res.status(400).json({ error: 'sandbox job required' }); return; }

    const stats = JSON.parse(job.stats || '{}');
    if (!stats.container_id) { res.status(400).json({ error: 'no container running' }); return; }

    const { name, description } = req.body;
    if (!name) { res.status(400).json({ error: 'name required' }); return; }

    const { dockerSnapshot } = await import('../pipeline/runtime/sandbox/introspect.js');
    const { createSandboxSnapshot } = await import('../db.js');

    const tag = await dockerSnapshot(stats.container_id, name);
    const snapId = createSandboxSnapshot({
      job_id: String(req.params.id),
      name,
      type: stats.sandbox_type || 'docker',
      description,
    });

    res.json({ id: snapId, name, tag });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/runtime/:id/snapshots
router.get('/:id/snapshots', (req: Request, res: Response) => {
  try {
    // getSandboxSnapshots is imported at the top of this file — the old
    // `require(...)` call here threw "require is not defined" in strict
    // ESM the moment the endpoint was hit.
    const snaps = getSandboxSnapshots(String(req.params.id));
    res.json({ data: snaps, total: snaps.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/runtime/:id/processes - list running processes
router.get('/:id/processes', async (req: Request, res: Response) => {
  try {
    const job = getRuntimeJobById(String(req.params.id));
    if (!job || job.type !== 'sandbox') { res.status(400).json({ error: 'sandbox job required' }); return; }

    const stats = JSON.parse(job.stats || '{}');
    if (!stats.container_id) { res.json({ data: [] }); return; }

    const { dockerTop } = await import('../pipeline/runtime/sandbox/introspect.js');
    const processes = await dockerTop(stats.container_id);
    res.json({ data: processes, total: processes.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/runtime/:id/resources - live resource stats
router.get('/:id/resources', async (req: Request, res: Response) => {
  try {
    const job = getRuntimeJobById(String(req.params.id));
    if (!job || job.type !== 'sandbox') { res.status(400).json({ error: 'sandbox job required' }); return; }

    const stats = JSON.parse(job.stats || '{}');
    if (!stats.container_id) { res.json({}); return; }

    const { dockerStats: getStats } = await import('../pipeline/runtime/sandbox/introspect.js');
    const live = await getStats(stats.container_id);
    res.json(live);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/runtime/:id/upload - upload file into sandbox
router.post('/:id/upload', async (req: Request, res: Response) => {
  try {
    const job = getRuntimeJobById(String(req.params.id));
    if (!job || job.type !== 'sandbox') { res.status(400).json({ error: 'sandbox job required' }); return; }

    const stats = JSON.parse(job.stats || '{}');
    if (!stats.container_id) { res.status(400).json({ error: 'no container' }); return; }

    const { host_path, container_path } = req.body;
    if (!host_path || !container_path) { res.status(400).json({ error: 'host_path and container_path required' }); return; }

    const { dockerCopyIn } = await import('../pipeline/runtime/sandbox/introspect.js');
    await dockerCopyIn(stats.container_id, host_path, container_path);
    res.json({ uploaded: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/runtime/:id/download/:path - download file from sandbox
router.get('/:id/download/*', async (req: Request, res: Response) => {
  try {
    const job = getRuntimeJobById(String(req.params.id));
    if (!job || job.type !== 'sandbox') { res.status(400).json({ error: 'sandbox job required' }); return; }

    const stats = JSON.parse(job.stats || '{}');
    if (!stats.container_id) { res.status(400).json({ error: 'no container' }); return; }

    const containerPath = '/' + (req.params as any)[0]; // everything after /download/
    const tmpPath = path.join(job.output_dir || '/tmp', `download-${Date.now()}`);

    const { dockerCopyOut } = await import('../pipeline/runtime/sandbox/introspect.js');
    await dockerCopyOut(stats.container_id, containerPath, tmpPath);
    res.download(tmpPath, path.basename(containerPath), () => {
      fs.unlink(tmpPath).catch(() => {});
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
