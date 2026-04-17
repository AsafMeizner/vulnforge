<!--
Thanks for contributing! Fill in whatever applies. Everything here
feeds directly into the review checklist in .github/copilot-instructions.md.
-->

## Summary

<!-- One paragraph. What and why, not how. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor (no behavior change)
- [ ] Docs only
- [ ] CI / tooling
- [ ] Breaking change (describe migration below)

## Checklist

- [ ] `npm test` passes locally
- [ ] `npx tsc --noEmit -p tsconfig.server.json` returns 0 errors
- [ ] I added or updated tests for the changed modules
- [ ] I updated `docs/` (or `README.md`) if I touched `server/sync/`,
      `server/auth/`, `server/integrations/`, `server/workers/`,
      `server/deployment/`, `electron/`, `Dockerfile.server`, or
      `scripts/install-server.*` - **or** I added `[skip-docs]` to the
      commit body with a good reason
- [ ] I ran the live app locally to spot-check the change (not just tests)

## Scope

<!-- If this touches more than one subsystem (frontend + server + docs + …), -->
<!-- note the per-subsystem impact so reviewers know what to scrutinize most. -->

## How to verify

<!-- Short steps a reviewer can run locally. Include curl snippets, -->
<!-- UI paths, or relevant env vars. -->

## Breaking changes

<!-- Delete if none. Otherwise: what breaks, who's affected, how to migrate. -->

## Related

<!-- Links to issues, design specs (docs/superpowers/specs/…), prior PRs. -->
