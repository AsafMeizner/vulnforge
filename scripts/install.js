#!/usr/bin/env node
/**
 * VulnForge Feature-Selective Installer
 *
 * Usage:
 *   node scripts/install.js                -- interactive
 *   node scripts/install.js --all           -- install everything
 *   node scripts/install.js --core --ai     -- specific features
 */

const cp = require("child_process");
const fs = require("fs");
const readline = require("readline");

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (q) => new Promise(r => rl.question(q, r));

function check(cmd) {
  try { cp.execSync(cmd + " --version", { stdio: "ignore" }); return true; }
  catch { return false; }
}

const features = [
  { id: "core",    name: "Core App",       size: "~50MB",   cmd: "npm install" },
  { id: "python",  name: "Python Tools",    size: "~20MB",   cmd: null, note: "Install Python 3 from python.org" },
  { id: "ai",      name: "AI (Ollama)",     size: "~4GB",    cmd: null, note: "Install from ollama.com, then: ollama pull qwen3:8b" },
  { id: "runtime", name: "Runtime Tools",   size: "~200MB",  cmd: null, note: "Install gdb, tcpdump, nmap, radare2" },
  { id: "docker",  name: "Docker Sandbox",  size: "~500MB",  cmd: null, note: "Install Docker Desktop from docker.com" },
  { id: "qemu",   name: "QEMU VMs",        size: "~1-10GB", cmd: null, note: "Install QEMU from qemu.org" },
  { id: "plugins", name: "Security Plugins", size: "~500MB", cmd: null, note: "Install from Plugins page in the app" },
];

async function main() {
  console.log("
=== VulnForge Installer ===");
  console.log("AI-Powered Vulnerability Research Platform
");

  const args = process.argv.slice(2);
  const all = args.includes("--all");

  for (const f of features) {
    const installed = f.id === "core" ? fs.existsSync("node_modules") : check(f.id === "docker" ? "docker" : f.id === "qemu" ? "qemu-system-x86_64" : f.id === "python" ? "python3" : f.id === "ai" ? "ollama" : f.id === "runtime" ? "gdb" : "semgrep");
    const status = installed ? "[installed]" : "[not found]";
    console.log("  " + f.id.padEnd(10) + f.name.padEnd(20) + f.size.padEnd(10) + status);
  }

  if (!all && args.length === 0) {
    const answer = await ask("
Install (comma-separated IDs or "all"): ");
    if (answer.trim() === "all") args.push("--all");
    else answer.split(",").forEach(s => args.push("--" + s.trim()));
  }

  console.log("
Installing...");
  for (const f of features) {
    if (!all && !args.includes("--" + f.id) && f.id !== "core") continue;
    console.log("
> " + f.name);
    if (f.cmd) { try { cp.execSync(f.cmd, { stdio: "inherit" }); } catch(e) { console.error("  Failed: " + e.message); } }
    if (f.note) console.log("  " + f.note);
  }

  console.log("
=== Done! Run: npm run dev ===");
  rl.close();
}

main().catch(console.error);