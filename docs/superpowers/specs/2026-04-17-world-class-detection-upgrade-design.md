# World-Class Detection Upgrade

**Date:** 2026-04-17
**Status:** Design - parallel dispatch approved
**Target:** VulnForge v0.2 → best vulnerability-finding platform available

## Goal

Close the gaps between VulnForge and "best in the world" by adding detection
capabilities competitors (Semgrep, CodeQL, SonarQube, Snyk) cover poorly or
not at all, plus onboarding polish that makes the tool accessible to new users
in any language and on any preference.

Two axes:

1. **Detection power** - find more real bugs, fewer false positives, deeper
   reasoning about exploit paths.
2. **Approachability** - setup wizard, in-app tutorials, multi-language UI,
   extended theme system.

## Non-Goals

- Rewriting the 6-stage pipeline orchestrator
- Replacing existing plugin integrations (Semgrep, Trivy, etc. stay as-is)
- Desktop distribution changes (Electron build untouched)
- "Perfect" coverage - moving target; this spec defines v0.2, not v∞

## Architecture

Work is partitioned into 9 **independent tracks**. Each track is implemented
by a dedicated subagent in the current working directory with strict rules:

- **Each agent writes only NEW files in a designated directory.**
- **No agent modifies existing production code.** Conflict zones
  (`orchestrator.ts`, `ai-verify.ts`, `chain-detector.ts`, `scanner/runner.ts`,
  `mcp/tools.ts`, `src/App.tsx`) are integrated sequentially by the lead
  (the main-branch integrator) after all agents return.
- Each agent adds its own tests alongside its new code.

### Detection tracks (backend, 6 subsystems F–K)

| Track | Subsystem                         | Scope                                                                                                                                                             | New directory                                                                  |
| ----- | --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| **F** | Supply-chain & backdoor detection | Malicious packages, typosquatting, postinstall payloads, secrets-in-git-history, weak/backdoored crypto, hidden admin routes, time-bombs, obfuscated payloads     | `server/pipeline/supply-chain/`                                                |
| **G** | Injection-class detectors         | SSTI, insecure deserialization (Python/Java/PHP/.NET/Ruby/Node families), NoSQL injection, LDAP injection, XPath injection, prompt injection, prototype pollution | `server/pipeline/detectors/injection/`                                         |
| **H** | Web/API/IaC detectors             | IaC misconfig (Terraform/CloudFormation/Dockerfile/k8s), GraphQL attacks, BOLA/BFLA, race/TOCTOU, mass assignment, CORS misconfig                                 | `server/pipeline/detectors/web/`                                               |
| **I** | Multi-hop dataflow & taint        | Source/sink database, lightweight call graph, cross-file taint propagation, full path reporting                                                                   | `server/pipeline/dataflow/`                                                    |
| **J** | AI accuracy & self-consistency    | N-vote self-consistency, cross-finding dedup, PoC-on-demand, confidence calibration                                                                               | `server/ai/accuracy/`                                                          |
| **K** | Reliability foundation            | Tool availability validation, per-tool metrics, pipeline metrics, test coverage for core detection modules                                                        | `server/metrics/`, `server/scanner/` (validator only), `tests/unit/` additions |

### UX tracks (frontend, 3 subsystems L–N)

| Track | Subsystem                   | Scope                                                                                                                                                 | New directory                                   |
| ----- | --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| **L** | Onboarding UX               | Extended setup wizard (beyond FirstLaunch), in-app guided tutorials (tours/walkthroughs), contextual help, keyboard shortcut cheatsheet               | `src/components/onboarding/`, `src/lib/tours/`  |
| **M** | Internationalization (i18n) | i18next setup, language detector, resource bundles for EN/ES/FR/DE/JA/ZH, language switcher, RTL support for Arabic/Hebrew, date/number localization  | `src/i18n/`, `src/locales/`                     |
| **N** | Extended theming            | Beyond dark/light - solarized, high-contrast (accessibility), dracula, nord, monokai; system preference detection; per-user persistence; theme editor | `src/themes/`, `src/components/ThemePicker.tsx` |

## Contracts (agent interfaces)

Each track exports a clean entry point the integrator calls from the
orchestrator or the frontend wiring:

```typescript
// Track F
export async function runSupplyChainScan(
  projectPath: string,
  metadata: ProjectMeta
): Promise<SupplyChainFinding[]>;

// Track G + H
export async function runDetectors(
  projectPath: string,
  languages: string[],
  deps: string[]
): Promise<Finding[]>;

// Track I
export async function analyzeDataflow(
  projectPath: string,
  finding: ScanFinding
): Promise<DataflowResult>;

// Track J
export async function verifyWithConsistency(
  finding: ScanFinding,
  config: ConsistencyConfig
): Promise<VerificationResult>;
export function dedupFindings(findings: ScanFinding[]): FindingGroup[];

// Track K
export async function validateTools(): Promise<ToolStatus[]>;
export function recordToolRun(metrics: ToolRunMetrics): void;

// Track L
export const SetupWizard: React.FC;
export const TutorialProvider: React.FC<{ children: ReactNode }>;

// Track M
export const I18nProvider: React.FC<{ children: ReactNode }>;
export function useTranslation(): { t: (key: string) => string; lang: string };

// Track N
export const ThemeProvider: React.FC<{ children: ReactNode }>;
export const THEMES: Record<string, ThemeDefinition>;
```

## Integration Plan (post-agent, done by lead)

After all 9 agents return:

1. **`server/pipeline/orchestrator.ts`** - invoke supply-chain + detectors in
   parallel with existing scan stage; call `validateTools()` at pipeline start
   and surface on pipeline record; wrap `recordToolRun` around each tool run.
2. **`server/pipeline/ai-verify.ts`** - replace per-finding AI call with
   `verifyWithConsistency`; prepend dataflow path from `analyzeDataflow` into
   the verify prompt; run `dedupFindings` before verification to reduce cost.
3. **`server/pipeline/chain-detector.ts`** - add new chain patterns derived
   from new detector CWEs (e.g., `prototype_pollution_to_privesc`,
   `ssrf_to_cloud_metadata_exfil`).
4. **`server/scanner/runner.ts`** - wrap `spawn` with metrics recording;
   tool-validator check before spawn.
5. **`server/mcp/tools.ts`** - add MCP tools: `run_supply_chain_scan`,
   `analyze_dataflow`, `dedup_findings`, `get_tool_metrics`,
   `validate_tools`, `run_detector`.
6. **`server/routes/stats.ts`** + new `server/routes/metrics.ts` - expose
   metrics endpoints for the UI.
7. **`src/App.tsx`** - wrap in `I18nProvider`, `ThemeProvider`,
   `TutorialProvider`; add `SetupWizard` before FirstLaunch component;
   expose theme picker + language switcher in Settings.
8. **`src/pages/Settings.tsx`** - add Theme tab and Language tab.
9. Run full test suite (`npm test`), fix any integration breakage.
10. Commit the integration as one logical bundle per subsystem.

## Risk Mitigation

- **Merge conflicts:** agents write only to disjoint new directories.
  Shared-file edits happen only in the integration phase.
- **Partial completion:** each track is independently mergeable. If one agent
  fails, the other 8 ship; failed track is respawned with a tighter prompt.
- **AI cost (Track J):** self-consistency with N=3 triples cost - gated
  behind a config flag (`consistency.enabled`) that defaults to false for
  solo-mode, true for team-mode pipelines.
- **Scope creep within tracks:** each agent prompt explicitly forbids
  modifying existing production files. Tests + fixtures only in new dirs.
- **Integration breakage:** lead runs the full test suite after each
  integration bundle (F → G → H → …) rather than all-at-once.

## Testing Approach

- Each track writes vitest unit tests alongside its code (same directory,
  `*.test.ts` sibling file) with fixtures under `__fixtures__/`.
- Test coverage target per track: ≥70% statements on new code.
- Integration tests (one per backend track) live in `tests/integration/`
  and are written during the integration phase.
- Full test suite must pass (`npm test`) before final commit.
- Frontend tracks must build cleanly (`npm run build`) and pass existing
  typecheck (`tsc --noEmit -p tsconfig.app.json`).

## Acceptance Criteria

- All 9 tracks shipped as working code with tests
- Full test suite green (currently 82 tests; expected ≥150 after)
- `npm run build` clean on both server and frontend
- New capabilities visible: supply-chain panel, detector results in findings,
  dataflow path in finding detail, theme picker in settings, language
  switcher in settings, tutorial overlay on first landing
- MCP tools list grows by ≥6 new tools

## Tracking

- Master tracker: this spec (`docs/superpowers/specs/2026-04-17-world-class-detection-upgrade-design.md`)
- Per-subsystem checklists: `todo/subsystems/{F,G,H,I,J,K,L,M,N}-*.md`
  (gitignored - local work-in-progress)
- Session log: `todo/sessions/2026-04-17-session-notes.md`
- Items marked `- [x]` as each agent ships its track
