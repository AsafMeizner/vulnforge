# Semgrep scan results

Static analysis results for project.

### [HIGH] src/auth/login.ts:42 - Hardcoded secret

The variable `JWT_SECRET` is assigned a literal value in source code.

```typescript
const JWT_SECRET = "super-secret-123";
```

**Impact:** If the repository leaks, all signed JWTs can be forged, enabling full authentication bypass. CWE-798.

**Reproduction:**

1. Clone the repository
2. Read src/auth/login.ts
3. Use the leaked secret to forge a valid JWT

**Suggested Fix:** Move the secret to an environment variable read at startup and fail fast if it is missing.

CVSS: 7.5 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

### [CRITICAL] src/api/upload.ts:88 - Arbitrary file write via path traversal

Untrusted `req.body.path` is passed to `fs.writeFileSync` without sanitization.

```typescript
fs.writeFileSync(req.body.path, req.body.content);
```

Impact: Attacker can overwrite arbitrary files on the server, including service binaries and systemd units, resulting in remote code execution.

Reproduction: POST { "path": "/etc/cron.d/pwn", "content": "* * * * * root curl …" }

Suggested Fix: Resolve the path against an allow-listed upload directory and reject anything escaping it via `..`.

CWE-22
