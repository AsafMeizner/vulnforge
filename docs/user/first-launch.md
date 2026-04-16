# First launch

When you open VulnForge for the first time, the app asks one question:

> **Solo or Team?**

## Solo

Pick this if you're a single researcher or you just want to kick the tires.

- Everything (frontend, backend, scanner, MCP, database) runs on your machine.
- No network is required.
- All data is `private` by default — never leaves your device.
- You can switch to team mode later (Settings → Deployment).

After picking Solo you land on the Hunt page, ready to paste a repo URL.

## Team

Pick this if your company runs a VulnForge server and you were given:

- A **public URL** (e.g. `https://vulnforge.acme.corp`).
- Either a **bootstrap token** (first admin on a fresh install) OR login credentials (SSO or username/password).

### Fresh server (you're the first admin)

1. Enter the public URL.
2. Paste the one-time bootstrap token the installer printed.
3. Create your admin account (username + password ≥ 8 chars).
4. Done — you're logged in as `admin`.

### Joining an existing server

1. Enter the public URL.
2. Click **Sign in with SSO** (if configured) or use username/password.
3. Done — you sync whatever your role allows.

## Why local-first in team mode?

Your desktop keeps its own SQLite + MCP + scanner stack even when connected to a team server. This means:

- You can keep working through WiFi drops, planes, coffee shops.
- Scans that need your laptop's GPU or specific tools run locally.
- Sensitive data tagged `private` **never** leaves your device.

The server is for **sharing**, not for being the only place data lives.

## Default row scope

Settings → Deployment → **Default row scope** controls what happens to new rows you create:

- `private` (default) — safer: nothing syncs unless you explicitly mark it `team`.
- `team` — everything syncs: good for small teams where everything is shared work.

Per-row override is always available via the scope pill in the row UI.

## Switching modes later

Settings → Deployment → **Switch mode** lets you move between Solo and Team.

- Solo → Team: prompts for server URL + login.
- Team → Solo: disconnects from the server. Your local DB is untouched; team-scoped rows remain locally but stop syncing.

No data is lost in either direction — the DB is the same shape in both modes.
