# Theme 1: Research Workspace - Cycle 1 MVP Design

**Status**: Approved, in implementation
**Owner**: Claude (parallel subagents)
**Date**: 2026-04-15

## Goal

Give researchers a persistent, pluggable workspace for capturing hypotheses, notes, and session context. The data model underlies everything else in the VulnForge Pro roadmap - exploit dev, disclosure ops, AI investigation mode all read from it.

## Architecture

- **Metadata in SQLite**: `notes`, `notes_providers`, `session_state` tables
- **Content in pluggable providers**: Local filesystem, Obsidian vault (MVP), Notion/Logseq/Generic MCP (deferred to Cycle 1b)
- **Universal format**: Markdown + YAML frontmatter - content round-trips losslessly through any backend
- **REST + MCP**: every operation exposed via both, so external Claude Code clients can participate

## Data Model

```sql
CREATE TABLE notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  provider TEXT NOT NULL DEFAULT 'local',
  external_id TEXT NOT NULL,           -- provider-specific ref (file path, page ID, etc.)
  title TEXT NOT NULL,
  type TEXT DEFAULT 'note',            -- note | hypothesis | observation | exploit-idea | todo
  status TEXT,                         -- open | investigating | confirmed | disproved | obsolete
  tags TEXT DEFAULT '[]',              -- JSON array
  project_id INTEGER,
  finding_ids TEXT DEFAULT '[]',       -- JSON array of linked finding IDs
  file_refs TEXT DEFAULT '[]',         -- JSON array of {file, line_start, line_end}
  confidence REAL,                     -- 0-1, mainly for hypotheses
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE notes_providers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL,                  -- local | obsidian | notion | logseq | mcp
  enabled INTEGER DEFAULT 1,
  is_default INTEGER DEFAULT 0,
  config TEXT DEFAULT '{}'             -- JSON config
);

CREATE TABLE session_state (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scope TEXT NOT NULL,                 -- global | project | finding
  scope_id INTEGER,
  key TEXT NOT NULL,
  value TEXT NOT NULL,                 -- JSON
  updated_at TEXT DEFAULT (datetime('now')),
  UNIQUE(scope, scope_id, key)
);
```

## Provider Interface

```typescript
export interface NoteMeta {
  title: string;
  type?: string;
  status?: string;
  tags?: string[];
  projectId?: number;
  findingIds?: number[];
  fileRefs?: Array<{ file: string; line_start?: number; line_end?: number }>;
  confidence?: number;
}

export interface NoteRef {
  externalId: string;
  title: string;
  updatedAt: string;
}

export interface NotesProvider {
  readonly name: string;
  readonly type: string;

  createNote(meta: NoteMeta, markdown: string): Promise<{ externalId: string }>;
  readNote(externalId: string): Promise<{ markdown: string; meta: NoteMeta }>;
  updateNote(
    externalId: string,
    markdown: string,
    meta?: Partial<NoteMeta>
  ): Promise<void>;
  deleteNote(externalId: string): Promise<void>;
  listNotes(filter?: { tag?: string; since?: string }): Promise<NoteRef[]>;
  searchNotes(query: string): Promise<NoteRef[]>;
  testConnection(): Promise<{ ok: boolean; error?: string }>;
}
```

## Note Format (markdown + frontmatter)

```markdown
---
vulnforge:
  id: 42
  type: hypothesis
  status: investigating
  confidence: 0.6
  project_id: 3
  finding_ids: [117, 118]
  file_refs:
    - { file: src/parser.c, line_start: 234, line_end: 260 }
  tags: [uaf, parser, pre-auth]
  created_at: 2026-04-15T14:30:00Z
  updated_at: 2026-04-15T16:45:00Z
---

# UAF in parseHeader connection teardown

Free happens in the error path, but callers still reference...
```

## REST API

```
# Notes
GET    /api/notes?project_id=X&type=X&status=X&tag=X
POST   /api/notes                { title, content, type?, project_id?, finding_ids?, tags? }
GET    /api/notes/:id            -> { ...meta, content }
PUT    /api/notes/:id            { title?, content?, status?, tags?, ... }
DELETE /api/notes/:id
POST   /api/notes/:id/link       { finding_id?, file?, line_start?, line_end? }
POST   /api/notes/search         { query, project_id? }

# Note providers
GET    /api/notes-providers
POST   /api/notes-providers      { name, type, config, enabled?, is_default? }
PUT    /api/notes-providers/:id
DELETE /api/notes-providers/:id
POST   /api/notes-providers/:id/test

# Session state
GET    /api/session?scope=X&scope_id=X
POST   /api/session              { scope, scope_id?, key, value }
DELETE /api/session/:key?scope=X&scope_id=X
POST   /api/session/clear        { scope, scope_id? }
```

## MCP Tools (appended to existing mcp/tools.ts)

**Notes:**

- `create_note(title, content, type?, project_id?, finding_ids?, tags?)`
- `list_notes(project_id?, type?, status?, tag?, limit?)`
- `read_note(id)`
- `update_note(id, content?, status?, tags?)`
- `search_notes(query, project_id?)`
- `link_note_to_finding(note_id, finding_id)`
- `list_hypotheses(project_id?, status?)` - shortcut for type='hypothesis'

**Session state:**

- `get_session_state(scope, scope_id?, key?)`
- `set_session_state(scope, scope_id?, key, value)`
- `get_active_context()` - returns most recent project, finding, hypothesis

## Frontend Components

1. **`src/components/NotesPanel.tsx`** - collapsible drawer showing notes filtered by scope (project or finding)
2. **`src/pages/HypothesisBoard.tsx`** - kanban view of hypotheses (open → investigating → confirmed → disproved)
3. **`src/components/QuickCapture.tsx`** - modal triggered by Ctrl-N, auto-links to current context
4. **`src/components/NoteEditor.tsx`** - textarea (Monaco deferred) + frontmatter metadata panel
5. **Settings additions** - new "Note Backends" section in Settings.tsx
6. **App.tsx** - register `#hypotheses` route, global Ctrl-N keybinding, replace any localStorage use with session API calls

## Parallel Build Plan

Main thread (sequential, foundation):

1. DB schema + migrations
2. Provider interface file (typed exports)
3. DB CRUD helpers

Then dispatch 4 parallel subagents (distinct file ownership):

**Subagent A - Providers** (`server/pipeline/notes/`)

- `server/pipeline/notes/provider.ts` - interface (re-exported from main thread's file)
- `server/pipeline/notes/local.ts` - local filesystem provider
- `server/pipeline/notes/obsidian.ts` - Obsidian vault provider (reads/writes markdown files)
- `server/pipeline/notes/index.ts` - provider registry/factory

**Subagent B - REST APIs** (`server/routes/`)

- `server/routes/notes.ts` - notes CRUD, linking, search
- `server/routes/session.ts` - session state CRUD
- Both register in `server/index.ts`

**Subagent C - MCP tools** (`server/mcp/tools.ts`)

- Append 7 notes tools + 3 session tools
- Uses DB + provider registry directly

**Subagent D - Frontend** (`src/`)

- `src/components/NotesPanel.tsx`
- `src/components/QuickCapture.tsx`
- `src/pages/HypothesisBoard.tsx`
- `src/lib/api.ts` - add notes/session client functions
- `src/App.tsx` - route + global keybinding
- `src/pages/Settings.tsx` - Note Backends section
- `src/pages/Projects.tsx` - embed NotesPanel
- `src/pages/FindingDetail.tsx` - embed NotesPanel + linking UI

Final integration (main thread):

- Build check
- Commit

## Cycle 1 Scope (what's IN)

- Notes provider interface + Local + Obsidian
- Full REST API for notes + session
- 10 MCP tools (notes + session)
- Notes panel on Project + Finding pages
- Hypothesis Board kanban
- Quick-capture modal
- Provider settings UI
- Server-side session state replacing localStorage

## Deferred to Cycle 1b

- Notion provider (needs API integration)
- Logseq provider (needs their HTTP API)
- Generic MCP provider (bridge config complexity)
- SQLite FTS5 full-text search
- Monaco editor (plain textarea for MVP)
- Project timeline view (needs Theme 4 git analyzer)
- Proof ladder UI (will hook into Theme 2 exploit workbench)

## Success Criteria

- Create a note from the UI, verify it appears as a markdown file in `data/notes/` (Local) or the configured Obsidian vault
- Create a hypothesis, see it on the Hypothesis Board, drag to new status, verify DB update
- External Claude Code session can `create_note` via MCP and it appears in UI
- Restart backend, session state restores correctly (last viewed project, open note)
- No localStorage usage remaining for session state
