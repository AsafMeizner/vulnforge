import { readFileSync, readdirSync, existsSync } from 'fs';
import path from 'path';

// ── Types ──────────────────────────────────────────────────────────────────

export interface ConfigFinding {
  file: string;
  line: number;
  check_id: string;
  category: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  title: string;
  description: string;
  fix: string;
  match: string;
}

// ── Check Definitions ──────────────────────────────────────────────────────

interface ConfigCheck {
  id: string;
  category: string;
  file_patterns: RegExp[];
  severity: ConfigFinding['severity'];
  title: string;
  description: string;
  fix: string;
  match_pattern: RegExp;
  negative?: boolean;  // true = finding if pattern NOT found (missing security control)
}

const CHECKS: ConfigCheck[] = [
  // ── Dockerfile checks ──────────────────────────────────────────────
  {
    id: 'DOCKER-001', category: 'Docker', severity: 'High',
    file_patterns: [/Dockerfile$/i],
    title: 'Container running as root',
    description: 'No USER directive found — container runs as root by default, increasing attack surface',
    fix: 'Add USER directive: USER nonroot:nonroot',
    match_pattern: /^\s*USER\s+/m,
    negative: true,
  },
  {
    id: 'DOCKER-002', category: 'Docker', severity: 'Medium',
    file_patterns: [/Dockerfile$/i],
    title: 'Using latest tag',
    description: 'FROM uses :latest or no tag — builds are not reproducible and may pull vulnerable versions',
    fix: 'Pin to a specific version tag (e.g., FROM node:20.11-alpine)',
    match_pattern: /^\s*FROM\s+\S+(?::latest\s*$|\s*$)/m,
  },
  {
    id: 'DOCKER-003', category: 'Docker', severity: 'High',
    file_patterns: [/Dockerfile$/i],
    title: 'Secrets in Dockerfile ENV',
    description: 'Environment variable appears to contain a secret (key, password, token)',
    fix: 'Use Docker secrets, build args with --secret, or runtime environment variables instead',
    match_pattern: /^\s*ENV\s+\S*(PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL|API_KEY)\s*=/im,
  },

  // ── CI/CD checks ───────────────────────────────────────────────────
  {
    id: 'CI-001', category: 'CI/CD', severity: 'Critical',
    file_patterns: [/\.github\/workflows\/.*\.ya?ml$/i],
    title: 'Dangerous pull_request_target trigger',
    description: 'Workflow uses pull_request_target with code checkout — allows arbitrary code execution from forks',
    fix: 'Use pull_request trigger instead, or never checkout PR code with pull_request_target',
    match_pattern: /pull_request_target/,
  },
  {
    id: 'CI-002', category: 'CI/CD', severity: 'High',
    file_patterns: [/\.github\/workflows\/.*\.ya?ml$/i],
    title: 'Untrusted input in run command',
    description: 'GitHub event data used directly in run: step — potential command injection',
    fix: 'Pass event data through environment variables instead of inline expressions',
    match_pattern: /run:.*\$\{\{\s*github\.event\./,
  },
  {
    id: 'CI-003', category: 'CI/CD', severity: 'High',
    file_patterns: [/\.github\/workflows\/.*\.ya?ml$/i],
    title: 'Workflow uses issue_comment trigger with checkout',
    description: 'Workflows triggered by issue comments can be exploited if they checkout and run PR code',
    fix: 'Validate comment author permissions before running any code',
    match_pattern: /issue_comment/,
  },

  // ── Environment file checks ────────────────────────────────────────
  {
    id: 'ENV-001', category: 'Environment', severity: 'Critical',
    file_patterns: [/\.env$/, /\.env\.local$/, /\.env\.development$/],
    title: 'Secrets in committed .env file',
    description: 'Environment file with potential secrets is tracked in repository',
    fix: 'Add .env to .gitignore and use .env.example with placeholder values',
    match_pattern: /\S*(PASSWORD|SECRET|KEY|TOKEN|PRIVATE)\s*=\s*\S+/i,
  },
  {
    id: 'ENV-002', category: 'Environment', severity: 'Medium',
    file_patterns: [/\.env/, /config\.(js|ts|json)$/i],
    title: 'Debug mode enabled',
    description: 'Debug mode is enabled — may expose sensitive information in errors',
    fix: 'Set DEBUG=false or NODE_ENV=production for production deployments',
    match_pattern: /\b(DEBUG\s*=\s*true|DEBUG\s*=\s*1|NODE_ENV\s*=\s*development)\b/i,
  },

  // ── Compiler hardening checks ──────────────────────────────────────
  {
    id: 'BUILD-001', category: 'Build', severity: 'Medium',
    file_patterns: [/Makefile$/, /CMakeLists\.txt$/i],
    title: 'Missing stack protector flag',
    description: 'Build does not enable stack protection — stack buffer overflows may be exploitable',
    fix: 'Add -fstack-protector-strong to CFLAGS/CXXFLAGS',
    match_pattern: /-fstack-protector/,
    negative: true,
  },
  {
    id: 'BUILD-002', category: 'Build', severity: 'Medium',
    file_patterns: [/Makefile$/, /CMakeLists\.txt$/i],
    title: 'Missing FORTIFY_SOURCE',
    description: 'Build does not enable FORTIFY_SOURCE — unsafe string functions not checked at compile time',
    fix: 'Add -D_FORTIFY_SOURCE=2 to CFLAGS/CXXFLAGS',
    match_pattern: /_FORTIFY_SOURCE/,
    negative: true,
  },
  {
    id: 'BUILD-003', category: 'Build', severity: 'Medium',
    file_patterns: [/Makefile$/, /CMakeLists\.txt$/i],
    title: 'Missing Position Independent Executable',
    description: 'Build does not produce PIE — ASLR cannot fully protect the executable',
    fix: 'Add -fPIE -pie to compiler and linker flags',
    match_pattern: /-fPIE|-pie/,
    negative: true,
  },

  // ── Kubernetes checks ──────────────────────────────────────────────
  {
    id: 'K8S-001', category: 'Kubernetes', severity: 'Critical',
    file_patterns: [/\.ya?ml$/i],
    title: 'Privileged container',
    description: 'Container runs in privileged mode — full host access, equivalent to root on the node',
    fix: 'Remove privileged: true and use specific capabilities instead',
    match_pattern: /privileged:\s*true/,
  },
  {
    id: 'K8S-002', category: 'Kubernetes', severity: 'High',
    file_patterns: [/\.ya?ml$/i],
    title: 'Host network enabled',
    description: 'Pod uses host networking — can intercept traffic from other pods and the node',
    fix: 'Remove hostNetwork: true unless absolutely required',
    match_pattern: /hostNetwork:\s*true/,
  },

  // ── Web server checks ──────────────────────────────────────────────
  {
    id: 'WEB-001', category: 'WebServer', severity: 'Medium',
    file_patterns: [/nginx\.conf$/i, /httpd\.conf$/i, /apache.*\.conf$/i],
    title: 'Directory listing enabled',
    description: 'Web server directory listing is enabled — exposes internal file structure',
    fix: 'Disable autoindex (nginx) or Options -Indexes (Apache)',
    match_pattern: /autoindex\s+on|Options.*Indexes/i,
  },
  {
    id: 'WEB-002', category: 'WebServer', severity: 'Medium',
    file_patterns: [/nginx\.conf$/i, /httpd\.conf$/i],
    title: 'Server version exposed',
    description: 'Server version header is not disabled — aids attacker reconnaissance',
    fix: 'Add server_tokens off (nginx) or ServerTokens Prod (Apache)',
    match_pattern: /server_tokens\s+off|ServerTokens\s+Prod/,
    negative: true,
  },
];

// ── Main Audit Function ────────────────────────────────────────────────────

/**
 * Audit all configuration files in a project for security issues.
 */
export function auditConfigs(projectPath: string): ConfigFinding[] {
  const findings: ConfigFinding[] = [];
  const files = collectConfigFiles(projectPath);

  for (const file of files) {
    const relPath = path.relative(projectPath, file);
    let content: string;
    try { content = readFileSync(file, 'utf-8'); } catch { continue; }

    for (const check of CHECKS) {
      // Does this check apply to this file?
      if (!check.file_patterns.some(p => p.test(relPath))) continue;

      if (check.negative) {
        // Finding if pattern NOT found (missing security control)
        if (!check.match_pattern.test(content)) {
          findings.push({
            file: relPath,
            line: 1,
            check_id: check.id,
            category: check.category,
            severity: check.severity,
            title: check.title,
            description: check.description,
            fix: check.fix,
            match: `Missing: ${check.match_pattern.source}`,
          });
        }
      } else {
        // Finding if pattern IS found (insecure config)
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (check.match_pattern.test(lines[i])) {
            findings.push({
              file: relPath,
              line: i + 1,
              check_id: check.id,
              category: check.category,
              severity: check.severity,
              title: check.title,
              description: check.description,
              fix: check.fix,
              match: lines[i].trim().slice(0, 120),
            });
            break; // One finding per check per file
          }
        }
      }
    }
  }

  return findings;
}

/**
 * Check compiler hardening flags for C/C++ projects.
 */
export function checkCompilerHardening(projectPath: string): ConfigFinding[] {
  return auditConfigs(projectPath).filter(f => f.category === 'Build');
}

// ── Helpers ────────────────────────────────────────────────────────────────

function collectConfigFiles(dirPath: string, depth = 0): string[] {
  if (depth > 4) return [];
  const files: string[] = [];
  const skipDirs = new Set(['.git', 'node_modules', 'vendor', '__pycache__', 'target', 'build', 'dist']);

  try {
    const entries = readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      if (skipDirs.has(entry.name)) continue;
      const full = path.join(dirPath, entry.name);

      if (entry.isDirectory()) {
        // Only recurse into known config directories
        if (entry.name === '.github' || entry.name === 'k8s' || entry.name === 'kubernetes' ||
            entry.name === 'deploy' || entry.name === 'docker' || entry.name === 'terraform' ||
            entry.name === 'workflows' || entry.name === '.circleci' || depth === 0) {
          files.push(...collectConfigFiles(full, depth + 1));
        }
      } else if (entry.isFile()) {
        const name = entry.name.toLowerCase();
        if (name === 'dockerfile' || name.endsWith('.yml') || name.endsWith('.yaml') ||
            name.startsWith('.env') || name === 'makefile' || name === 'cmakelists.txt' ||
            name.endsWith('.conf') || name.endsWith('.tf') || name === 'docker-compose.yml') {
          files.push(full);
        }
      }
    }
  } catch { /* ignore */ }
  return files;
}
