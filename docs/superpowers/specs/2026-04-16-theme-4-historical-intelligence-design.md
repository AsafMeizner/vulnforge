# Theme 4: Historical Intelligence

**Status**: In implementation
**Cycle**: 3

## Goal

Turn git history into actionable intelligence. Find when bugs were introduced, hunt variants of disclosed CVEs across all imported projects, and auto-sync from NVD to enrich existing scan findings.

## Components

### 1. Git Bisect Wrapper (runtime executor)

New executor: `server/pipeline/runtime/git/bisect.ts` implementing `RuntimeJobExecutor` (type='bisect', tool='git').

Config:
```typescript
{
  project_id: number;
  good_ref: string;              // known-good commit (e.g. "v1.0.0")
  bad_ref: string;               // known-bad commit (e.g. "HEAD")
  test_command: string;          // shell command — exit 0 = good, non-zero = bad
  timeout_per_test?: number;     // per-commit timeout in seconds
}
```

Executor runs `git bisect start {bad_ref} {good_ref}` then `git bisect run bash -c '{test_command}'`, streams output, records the final "first bad commit" and its diff.

### 2. Patch Analyzer

New module: `server/pipeline/history/patch-analyzer.ts`

Functions:
- `analyzePatch(diff: string)` — extract added/removed code, identify security-relevant patterns (new bounds checks, removed auth checks, type changes on size params), generate a pattern fingerprint
- `analyzeCommit(projectPath, sha)` — git show + analyze
- `extractVulnPattern(patch)` — derive a grep pattern from the removed code to hunt variants

### 3. CVE Variant Hunter (extend existing)

The existing `server/pipeline/cve-hunter.ts` has a pattern database. This cycle extends it with:
- Frontend UI to browse patterns, add new ones from patches, run cross-project hunts
- REST endpoints to list/run patterns
- Historical findings correlation (when a pattern matches, show which projects have it)

### 4. NVD/GHSA Sync

New module: `server/pipeline/history/nvd-sync.ts`

Functions:
- `syncRecentCVEs(sinceDate: string)` — fetch recent CVEs from NVD API, store metadata
- `matchDependencies(projectId)` — given a project's dependencies from git.ts extractor, cross-reference with CVE list
- Scheduled job: runs daily via a new "scheduled tasks" system (lightweight: just a setInterval in server)

### 5. History Page (frontend)

New page: `src/pages/History.tsx` — accessible from projects, shows:
- Git analysis summary (security commits, hot files — from existing git-analyzer)
- Bisect jobs list (uses runtime_jobs with type='bisect')
- CVE pattern library with "Run Hunt" button
- NVD dependency matches for imported projects

## Data Model

Add tables:
```sql
CREATE TABLE bisect_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id TEXT NOT NULL,
  first_bad_commit TEXT,
  first_bad_date TEXT,
  commit_message TEXT,
  diff TEXT,
  author TEXT,
  tests_run INTEGER DEFAULT 0,
  FOREIGN KEY (job_id) REFERENCES runtime_jobs(id)
);

CREATE TABLE cve_intel (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL UNIQUE,
  published TEXT,
  modified TEXT,
  severity TEXT,
  cvss_score REAL,
  description TEXT,
  affected_products TEXT,    -- JSON array
  references TEXT,            -- JSON array
  synced_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE cve_project_matches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL,
  project_id INTEGER NOT NULL,
  match_reason TEXT,          -- 'dependency', 'pattern', 'manual'
  dependency_name TEXT,
  dependency_version TEXT,
  confidence REAL,
  matched_at TEXT DEFAULT (datetime('now'))
);
```

## Build Order

1. Spec (this doc)
2. DB schema + CRUD
3. Patch analyzer module
4. Git bisect executor (plug into runtime job framework)
5. NVD sync module + scheduled task
6. REST routes for history
7. MCP tools: `start_bisect`, `analyze_patch`, `sync_nvd`, `list_cve_intel`, `get_project_cve_matches`, `run_cve_hunt`
8. Frontend History page
9. Integration + commit

## Success Criteria

- Start a bisect job via MCP → watch it run in Runtime page → see final bad commit
- Sync NVD → see CVE list populate → project dependencies automatically cross-referenced
- Run CVE pattern hunt across all projects → results appear as scan findings
- Patch analyzer takes a commit hash → extracts the security-relevant diff
