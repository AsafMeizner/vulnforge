/**
 * QEMU VM Executor - full virtual machine support.
 */
import cp from "child_process";
import { promisify } from "util";
import { promises as fs } from "fs";
import { createWriteStream } from "fs";
import path from "path";
import net from "net";
import { getRuntimeJobById } from "../../../db.js";
import { findFreePort } from "./introspect.js";
import type { RuntimeJobExecutor, JobContext, QemuSandboxConfig } from "../types.js";

const runCmd = promisify(cp.execFile);

const ARCH_BIN: Record<string, string> = {
  x86_64: "qemu-system-x86_64",
  i386: "qemu-system-i386",
  arm: "qemu-system-arm",
  aarch64: "qemu-system-aarch64",
  mips: "qemu-system-mips",
  riscv64: "qemu-system-riscv64",
};

export class QemuExecutor implements RuntimeJobExecutor {
  readonly type = "sandbox" as const;
  readonly tool = "qemu";

  validate(config: Record<string, any>): void {
    const cfg = config as QemuSandboxConfig;
    if (!cfg.disk_image) throw new Error("disk_image required (.qcow2/.img/.iso)");
  }

  async execute(ctx: JobContext): Promise<void> {
    const cfg = ctx.config as QemuSandboxConfig;
    const arch = (cfg as any).arch || "x86_64";
    const qemuBin = ARCH_BIN[arch] || "qemu-system-" + arch;

    try { await runCmd(qemuBin, ["--version"], { timeout: 5000 }); }
    catch { throw new Error(qemuBin + " not found. Install QEMU."); }

    try { await fs.access(cfg.disk_image); }
    catch { throw new Error("Disk image not found: " + cfg.disk_image); }

    const qmpPort = cfg.qmp_port || await findFreePort(4440, 4500);
    const vncPort = cfg.vnc_port || await findFreePort(5900, 5999);
    const vncDisplay = vncPort - 5900;
    const sshPort = cfg.ssh_port || await findFreePort(2222, 2299);

    const args: string[] = [];
    args.push("-m", cfg.memory || "1G");
    args.push("-smp", String(cfg.cpus || 2));
    const fmt = cfg.disk_image.endsWith(".qcow2") ? "qcow2" : "raw";
    args.push("-drive", "file=" + cfg.disk_image + ",format=" + fmt);
    if (cfg.snapshot_mode) args.push("-snapshot");
    args.push("-vnc", ":" + vncDisplay);
    args.push("-qmp", "tcp:127.0.0.1:" + qmpPort + ",server,nowait");
    if (cfg.network !== "tap") {
      args.push("-netdev", "user,id=net0,hostfwd=tcp::" + sshPort + "-:22");
      args.push("-device", "virtio-net-pci,netdev=net0");
    }
    args.push("-display", "none");

    ctx.updateStats({
      sandbox_type: "qemu", pid: 0, vnc_port: vncPort,
      qmp_port: qmpPort, ssh_port: sshPort, arch,
      image: cfg.disk_image, paused: false,
    });

    ctx.emit({ type: "start", data: { qemu: qemuBin, vnc_port: vncPort, qmp_port: qmpPort, ssh_port: sshPort } });

    const logPath = path.join(ctx.outputDir, "output.log");
    const logStream = createWriteStream(logPath, { flags: "a" });
    const child = cp.spawn(qemuBin, args, { stdio: ["ignore", "pipe", "pipe"] });
    child.stdout?.pipe(logStream);
    child.stderr?.pipe(logStream);
    ctx.updateStats({ pid: child.pid });

    const startTime = Date.now();

    try {
      while (true) {
        await new Promise(r => setTimeout(r, 3000));
        if (ctx.shouldStop()) break;
        if (child.exitCode !== null) break;

        const uptime = Math.round((Date.now() - startTime) / 1000);
        ctx.updateStats({ uptime_seconds: uptime });

        if (cfg.timeout && cfg.timeout > 0 && (Date.now() - startTime) / 1000 > cfg.timeout) break;
      }
    } finally {
      if (child.exitCode === null) {
        child.kill("SIGTERM");
        await new Promise(r => setTimeout(r, 3000));
        if (child.exitCode === null) child.kill("SIGKILL");
      }
      logStream.end();
    }
  }
}
