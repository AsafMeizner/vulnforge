# Security policy

## Reporting a vulnerability

**Please do NOT open a public issue for security bugs.**

Instead, file a private security advisory:
<https://github.com/AsafMeizner/vulnforge/security/advisories/new>

Include:

- Affected component (frontend, backend route, pipeline module, sync
  protocol, auth, MCP tool, etc.).
- Affected version (git SHA or tag).
- Deployment mode (solo desktop, team-server Docker, team-server
  bare-metal).
- Reproduction steps - exact request/response, curl snippet, or test
  harness is ideal.
- Impact - what an attacker can achieve.

## Response timeline

As a solo-maintained project today, commitments are best-effort:

| Stage                    | Target                                                             |
| ------------------------ | ------------------------------------------------------------------ |
| First acknowledgement    | ≤ 3 business days                                                  |
| Triage + severity rating | ≤ 7 business days                                                  |
| Fix or mitigation        | Depends on severity; critical issues prioritized over feature work |

## Scope

In-scope:

- `server/**` (Express backend, MCP, sync, auth, pipeline, workers, integrations)
- `src/**` (frontend)
- `electron/**`
- `Dockerfile.server`, `docker-compose.server.yml`
- `scripts/install-server*`, `scripts/bootstrap.mjs`, `scripts/migrate.mjs`
- The JWT + refresh-token protocol
- Server-proxied capability manifest invocation paths

Out of scope:

- Third-party plugins (Semgrep, Trivy, etc.) - report upstream.
- Bugs in Node / SQLite / bcryptjs / jsonwebtoken - report upstream.
- Issues reproducible only in heavily modified forks.

## Hall of fame

Credit is given in release notes unless the reporter opts out.
