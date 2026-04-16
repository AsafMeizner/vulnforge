# AI providers: local vs server-provided

VulnForge routes AI tasks (triage, verify, deep-analysis, embed, summary) to a provider per your rules in **AI → Routing**.

## Two sources

### Local providers

API keys you paste into your desktop. Keys stay on your machine and never sync. Examples: your personal Claude API key, a local Ollama running on your GPU, OpenAI with your own billing.

### Server providers

In team mode, your company's server can expose its own pool of providers. Keys live on the server; clients invoke by name without ever seeing them.

Examples of why a company would do this:
- **Cost control** — everyone uses one metered API key instead of individual expense reports.
- **Privacy** — scan output gets routed through a local on-prem Ollama instead of a third-party API.
- **Capability pooling** — expensive Claude Opus calls go through a team budget; cheaper triage work uses the server's local model.

Server providers appear prefixed in your picker:

```
Local: claude-opus
Local: ollama-local
Server: team-triage       ← invoked via server proxy
Server: team-deep         ← invoked via server proxy
```

## Controls for users

- **AI → Providers** tab — manage your local providers.
- **AI → Routing** tab — assign tasks to specific providers (local or server).
- You can mix freely: `triage → Server: team-triage` and `deep-analysis → Local: claude-opus`.

## Controls for admins (server mode)

Settings → AI → **Team providers** (admin-only):

- Add / edit / remove team-wide providers.
- Set allowed task tags per provider.
- Enable/disable the capability manifest globally (`capability_manifest_enabled`).

If the manifest is disabled, clients see an empty server-provider list — it looks like solo-mode for AI purposes even while sync still works.

## Per-request proxying

When your routing chooses a `Server: X` provider, the call goes:

```
Desktop → POST /api/server/ai/invoke {capability: "team-triage", task: "triage", payload: {...}}
Server → looks up provider by name → invokes upstream with server-side creds
Server → streams response back over the same request
Desktop → treats it like a local call
```

Request is attached to `req.user.id` server-side so audits show *who* asked. You see latency proportional to upstream + network — typically 1-3 s slower than a local call but with centralized control.

## What never leaves your device

- Your local provider API keys.
- Local model weights (Ollama).
- The content of `private`-scoped findings — those are never eligible for server-proxied AI calls in the first place (routing rules respect scope).

## Fallback chains

In **AI → Routing**, every task can define a chain:

```
triage → [Server: team-triage, Local: ollama-local, Local: claude-haiku]
```

If the first errors or rate-limits, the next is tried automatically. Useful to not fail a scan because your one provider is down.
