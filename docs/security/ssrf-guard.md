# SSRF guard (CR-12)

## What this covers

Any user-controlled URL that the VulnForge server subsequently fetches
is a potential SSRF (Server-Side Request Forgery) vector. Left
unchecked, an operator inside an AWS VM could point the AI provider
`base_url` at `http://169.254.169.254/latest/meta-data/iam/...` and
exfiltrate IAM credentials via the AI triage loop. Or an attacker-owned
OIDC IdP could return a discovery document whose `token_endpoint`
points at the server's own loopback admin API.

The guard lives in `server/lib/net.ts` and is wired into every place
the server reads a URL from untrusted input and then fetches it.

## What the guard rejects

| Class | Examples |
|---|---|
| Non-http(s) protocols | `file://`, `gopher://`, `javascript:`, `ftp://` |
| IPv4 private / reserved | RFC1918 (`10/8`, `172.16/12`, `192.168/16`), CGNAT (`100.64/10`), link-local (`169.254/16`), loopback (`127/8`), broadcast / multicast / test-nets, `0.0.0.0/8` |
| IPv6 non-global | `::`, `::1`, ULA (`fc00::/7`), link-local (`fe80::/10`), multicast (`ff00::/8`) |
| IPv4-mapped-IPv6 bypass | `::ffff:10.0.0.1` - unwrapped + re-checked against the IPv4 list |
| Cloud metadata hostnames | `metadata.google.internal`, `metadata.azure.com`, `instance-data.ec2.internal` |
| DNS-rebinding | Hostname resolution happens inside the guard and each returned A/AAAA record is checked against the same blocklist |
| Plaintext http | `http://` to anything non-loopback (prevents passive-MITM on leaked tokens) |

## Mode-dependent rules

- **Desktop mode** (`isDesktopMode()` true): `localhost` / `127.0.0.1` /
  `::1` pass. Reason: Ollama on `:11434`, local tool runners, local
  OIDC (Keycloak-on-my-laptop) all legitimately need loopback.
- **Server mode**: loopback is refused outright. Nothing user-facing
  runs on loopback in a team deployment, and allowing it re-opens
  SSRF-to-admin.

The `allowLocalhost` option lets callers override per-call, but that's
rare. Metadata hostnames are refused in every mode regardless.

## API surface

```ts
// Throws SsrfError (status: 400, code: 'SSRF_REFUSED') on any reject.
// Does DNS at validation time, so a hostname trick (evil.com flipping
// to 127.0.0.1) fails here, not at fetch-time.
await assertSafeExternalUrl(url, {
  field: 'base_url',     // shown in the rejection message
  allowLocalhost?: boolean,
  allowHttp?: boolean,
  allowedHosts?: string[],
  allowedProtocols?: string[],
});

// Boolean variant for "validate and fall through" paths.
await isSafeExternalUrl(url, opts): Promise<boolean>;

// Resolve a hostname and return the first non-blocked address. Used
// for fetch-time IP pinning (narrow the DNS-rebind window).
await resolveAndValidate(hostname, opts): Promise<{address, family}>;
```

## Where it is wired

**Write-time** (reject bad URLs before they land in the DB):

- `POST /api/ai/providers` and `PUT /api/ai/providers/:id` - validates
  `body.base_url` before calling `upsertAIProvider()`.
- `upsertOidcProvider()` - validates `row.issuer_url` before the
  INSERT OR REPLACE. No HTTP route calls this yet, but the guard is
  in the function so future admin CRUD inherits it.

**Fetch-time** (reject URLs returned from upstream responses):

- `discoverProvider()` in `server/auth/oidc.ts` - re-validates the
  stored `issuer_url` AND every URL the discovery document returns
  (`token_endpoint`, `userinfo_endpoint`, `jwks_uri`). A malicious IdP
  can no longer point the subsequent token-exchange fetch at the
  server's own loopback.

**Not currently wired** (future scope):

- Integration webhook URLs (Jira / Linear / Slack). These live in
  `integrations.config` JSON and don't have a single ingress point; a
  follow-up pass should walk the integration registrar.
- Git clone targets. The `git` pipeline step uses a separate
  `validateGitUrl()` helper that enforces https + host allowlist.

## TOCTOU (DNS rebinding) limits

`assertSafeExternalUrl` resolves the hostname once, validates the
resolved IP(s), and returns. The subsequent `fetch()` call re-resolves
the hostname through Node's default resolver, so there is a brief
window where a malicious DNS server could flip the A record.

To close that window completely, callers should use
`resolveAndValidate()` and pin the resolved IP onto the fetch agent's
`lookup` option. Not every caller does this yet - it's safe to add
per-hotspot rather than eagerly everywhere, because the guard rejects
the dangerous classes of literal destinations upstream.

## Unit tests

`tests/unit/ssrf-guard.test.ts` exercises every blocklist branch
explicitly (25 cases). The pattern matters: a SSRF regression fails
silently at runtime (the fetch succeeds, data flows) so the test
coverage is the difference between "hole opens silently" and "hole
opens loudly with a red CI".

## References

- `server/lib/net.ts` - guard implementation
- `server/index.ts` POST/PUT `/api/ai/providers` - write-time wiring
- `server/auth/oidc.ts::discoverProvider` - fetch-time wiring
- `tests/unit/ssrf-guard.test.ts` - coverage
