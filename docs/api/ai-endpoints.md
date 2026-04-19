# /api/ai/* endpoints

All `/api/ai/*` endpoints live in `server/routes/ai.ts`. They sit
behind the same `authMiddleware` + viewer-is-read-only global guard
as every other `/api/*` route, plus each writer calls
`assertPermission(req, 'ai', <action>, res)` with one of:

- `'invoke'` - chat / triage / analyze / remediate / agent (team-AI
  budget counter goes here).
- `'admin'` - provider CRUD, routing rules, preset apply.

Every prompt builder in these endpoints goes through the CR-14 fence
(`withInjectionGuard` + `fenceUntrusted`), so user-supplied
description / code_snippet / tool_output can't rewrite the task.
Short fields (title, severity, CWE, file path) are
`sanitizeInline`d into narrative prose.

## Chat

`POST /api/ai/chat`
Permission: `ai.invoke`

Free-form chat against the current routing target. Body:

```json
{
  "messages": [
    { "role": "user", "content": "Explain this CVE" }
  ],
  "systemPrompt": "optional override",
  "temperature": 0.3,
  "maxTokens": 2048
}
```

Response: `{ response, model, provider }`.

## Triage

`POST /api/ai/triage/:id`
Permission: `ai.invoke`

Canonical triage via `server/ai/pipeline.ts::triageFinding(id)`.
Returns `202` immediately; the actual work runs detached with its
own error handler. Poll `/api/vulnerabilities/:id` to see the
resulting `ai_triage` column.

`POST /api/ai/triage-legacy/:id`
Permission: `ai.invoke`

Legacy string-form triage that writes directly back to
`vulnerabilities.ai_triage`. Prefer the canonical endpoint above.

## Suggest-fix

`POST /api/ai/suggest-fix`
Permission: `ai.invoke`

Body: `{ vuln_id }`. Returns `{ suggested_fix, fix_diff }`.
Persists back to the vulnerability row if no `suggested_fix`
existed yet.

## Deep analyze

`POST /api/ai/deep-analyze`
Permission: `ai.invoke`

Body: `{ vuln_id }`. Returns a long-form analysis string covering
exploitability / impact / root cause / verification / fix strategy /
CVE comparisons / disclosure path / tier verdict.

## Agent

`POST /api/ai/agent`
Permission: `ai.invoke`

Body: `{ goal: string, max_steps?: number }`. `max_steps` is
server-capped at `AGENT_MAX_STEPS` (25) regardless of caller input.

The agent loop fences every tool result because DB rows may carry
attacker-authored content from scanned repositories.

## Models

`GET /api/ai/models`
Permission: any authenticated user

Returns the full model registry (provider, pricing, context window,
capability flags).

## Routing

`GET /api/ai/routing`
Permission: any authenticated user

Returns the current routing rules (task → provider → model chain).

`PUT /api/ai/routing`
Permission: `ai.admin`

Body: array of `{ task, provider, model, fallback? }`. Replaces the
stored rule set.

`GET /api/ai/routing/presets`
Permission: any authenticated user

Lists available presets (cheap-and-fast, quality-first, etc.) with
their human-readable description.

`POST /api/ai/routing/presets/:name`
Permission: `ai.admin`

Applies the named preset.

## Providers

`GET /api/ai/providers`
Permission: any authenticated user

Lists configured AI providers with API keys masked as `***`.

`POST /api/ai/providers`
Permission: `ai.admin`

Body is pick-listed through `PROVIDER_WRITABLE`
(`name | model | api_key | base_url | enabled | config`) so extra
columns in the request are silently dropped. `base_url` goes
through `assertSafeExternalUrl` before persistence.

`PUT /api/ai/providers/:id`
Permission: `ai.admin`

Same allowlist as POST. `api_key` of `'***'` (the masked value in
the list response) is ignored so editing doesn't overwrite the real
key.

`DELETE /api/ai/providers/:id`
Permission: `ai.admin`

## Error shape

All endpoints throw through the CR-11 global wrapper, so errors
return `{ error, code?, request_id }`. Production builds redact
`err.message` to `'Internal server error'`; development keeps the
message + first 8 stack frames. Query-string secrets (code, state,
token, key, api_key, secret, password, id_token, access_token) are
redacted before the URL hits stdout.

## References

- `server/routes/ai.ts` - implementation
- `server/ai/prompts/fence.ts` - CR-14 fence helpers
- `server/lib/net.ts` - SSRF guard (applied to base_url)
- `docs/security/prompt-fencing.md` - threat model
