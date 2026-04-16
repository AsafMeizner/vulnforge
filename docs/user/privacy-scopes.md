# Privacy scopes

Every finding, project, note, and report you create has a **scope** that controls who can see it.

## Three scopes

### 🔒 `private`

Stays on your desktop. Never syncs anywhere.

**Use for:**
- Personal research notes you're not ready to share.
- Findings in client codebases under NDA.
- Half-baked hypotheses you'll refine first.

### 👥 `team`

Syncs to the team server; every authenticated team member sees it.

**Use for:**
- Production findings.
- Shared projects.
- Completed reports.
- Any work that benefits from collaboration.

### 🌐 `pool`

Opt-in, anonymized, shared across organizations.

**Use for:**
- Interesting CVE patterns you want the broader community to hunt across their codebases.
- Public-OSS findings where collective intelligence helps.

**Anonymization is automatic before a pool row reaches the server:**
- `owner_user_id` is stripped.
- URLs are reduced to scheme + host + path (no query params, no auth).
- File paths become just the basename (`/home/alice/code/secret/util.c` → `util.c`).

You can always review what a row will look like after anonymization via the "Preview pool submission" button before committing.

## Picking a scope

Every row has a **scope pill** next to its title. Click to change.

Default scope for new rows: **Settings → Deployment → Default row scope** (default: `private`).

## What is NEVER synced regardless of scope

- API keys (AI providers, integrations).
- Local plugin binaries and configuration.
- OS-local filesystem paths (like your Obsidian vault location).
- Refresh tokens.
- UI preferences.

These live in tables marked `UNSYNCABLE_TABLES` — the sync transport refuses to touch them even if buggy code asked it to.

## Moving data between scopes

- **Private → Team**: the row picks up a fresh `server_updated_at_ms` on first sync and becomes visible to the team.
- **Team → Private**: the row stops being pushed from your desktop. Other team members *still have it* from their own sync cursors; you'd need an admin to delete it server-side if you want it gone for everyone.
- **Anything → Pool**: goes through the separate `/api/pool/push` endpoint with anonymization. The original row on your desktop is untouched — only the sanitized copy goes to the pool.

## FAQ

**Q: Can an admin read my `private` rows?**
A: Not through the server — private rows never go to the server. If an admin has physical access to your desktop, they can of course read your local DB.

**Q: My team member marked a finding `private` then `team` back and forth. Does the server see every change?**
A: Sync-wise, only when it's `team` does it flow. But a row that was ever `team` keeps its `sync_id` and `server_updated_at_ms`; toggling to `team` again re-enables push of the latest version, overwriting the server's copy on conflict.

**Q: Can I bulk-change scope for all my private rows to team?**
A: Yes — Settings → Deployment → **Bulk scope**. Pick a filter (e.g. "my rows in project X") and a target scope.
