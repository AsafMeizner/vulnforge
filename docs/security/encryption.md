# At-rest encryption (CR-08 / CR-09 / CR-10)

## What this covers

VulnForge encrypts the three kinds of secrets that previously lived as
plaintext inside `vulnforge.db`:

- **AI provider API keys** (`ai_providers.api_key`) - CR-08
- **OIDC client secrets** (`oidc_providers.client_secret`) - CR-09
- **Integration configs** (`integrations.config` - whole JSON blob, so
  webhook URLs + bot tokens + per-integration API keys are all opaque
  at the SQLite layer) - CR-10

The threat model is "attacker reads the DB file": a one-time SQL export,
a backup tape that walked off, a `scp`-gone-wrong. Before this work,
that exposure handed the attacker live credentials for every connected
upstream. With envelope encryption the attacker also needs the master
data key, which never sits inside the DB.

Password hashes (bcrypt) and refresh-token hashes (bcrypt) were already
one-way and stay that way. JWT signing secret lives in `.env`, not the
DB.

## Envelope format

All encrypted values carry a `vf1:` prefix. The stored string looks
like:

```
vf1:<base64(iv || tag || ciphertext)>
```

- **Algorithm:** AES-256-GCM (authenticated encryption - any tampering
  fails decryption).
- **IV:** 12 random bytes per encryption.
- **Tag:** 16-byte GCM auth tag.
- **Ciphertext:** UTF-8 bytes of the plaintext.

The prefix doubles as an "is this already encrypted?" check so every
helper is idempotent. `encryptSecret("vf1:AAAA")` short-circuits to
the same value; a future rotation can ship `vf2:` without breaking the
old reader.

## Master key lifecycle

Resolved in this order by `server/lib/crypto.ts::getMasterKey()`:

1. `VULNFORGE_DATA_KEY` env var (base64-encoded 32 bytes). First-class
   because it lets operators keep the key outside the data directory
   (Kubernetes Secret, Docker swarm secret, HashiCorp Vault agent,
   systemd `LoadCredential=`).
2. `<VULNFORGE_DATA_DIR>/master.key` file. Desktop-mode default path.
   Created `chmod 600` on first boot with 32 bytes from
   `crypto.randomBytes`. Permissions are re-checked at startup.
3. Neither present AND `isServerMode()` → **refuse to start**. The
   server logs `[crypto] no master key available in server mode` and
   exits 1. Desktop mode is allowed to bootstrap the file automatically
   since the process owns its own `userData` directory.

## Helper API (`server/lib/crypto.ts`)

```ts
encryptSecret(plaintext: string): string   // always returns vf1:...
decryptSecret(envelope: string): string    // plain passthrough if no vf1: prefix
isEncrypted(value: string): boolean        // vf1: prefix check
```

All three are synchronous. They throw `CryptoError` on:

- Corrupt ciphertext (tag mismatch).
- Malformed base64.
- Missing master key (only possible in server mode via the hard refuse).

## Migration

Boot-time idempotent migrations walk the three affected tables and wrap
any unprefixed row:

- `migrateAIProviderSecrets()` (called from `initDb()`)
- `migrateOidcSecrets()` (called from `initDb()`)
- `migrateIntegrationSecrets()` (called from `initDb()`)

Each one is safe to run repeatedly. `isEncrypted()` short-circuits rows
that already have the `vf1:` prefix, so restarting the server after a
migration does not double-wrap anything.

## Rotation story

Today: one master key. To rotate, operator needs to:

1. Decrypt all three tables with the current key into a temporary
   mapping.
2. Set the new key (env var flip or `master.key` replace).
3. Re-encrypt all three tables.

A future `vf2:` version will support migration-by-envelope without a
full decrypt-and-re-encrypt cycle (read-your-write compatibility with
mixed `vf1:` and `vf2:` rows). That is not shipped yet.

## What ISN'T encrypted

- Row-level metadata: finding titles, descriptions, code snippets, CVE
  text, anything that shows up in the UI's rendered content. These are
  treated as application data, not secrets.
- Ticket numbers, sync cursors, user display names.
- The DB file's SQLite page structure itself. `.db` is not opaque; a
  reader still sees table names, row counts, and all non-encrypted
  columns. The encryption is scoped to the three credential columns by
  design - full-DB encryption would conflict with the sync protocol
  (server needs to serve rows by content).

## References

- `server/lib/crypto.ts` - helpers
- `server/db.ts::migrateAIProviderSecrets()` - AI migration
- `server/auth/oidc.ts::migrateOidcSecrets()` - OIDC migration
- `server/db.ts::migrateIntegrationSecrets()` - integrations migration
- `tests/unit/crypto.test.ts` - unit coverage (roundtrip, idempotency,
  tamper detection)
