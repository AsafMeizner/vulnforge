/**
 * Tool description lookup - maps a scanner's `tool_name` to a
 * human-readable one-sentence explanation of what the tool checks for.
 *
 * Loads `server/data/tool-descriptions.json` once on first call and
 * caches the result for the process lifetime. Tolerant of missing files
 * (returns `null`) so dev/test setups without the data file keep working.
 */
import { readFileSync, existsSync } from 'fs';
import path from 'path';

type DescriptionMap = Record<string, string>;

let _cached: DescriptionMap | null = null;

function loadDescriptions(): DescriptionMap {
  if (_cached) return _cached;
  const candidates = [
    path.join(process.cwd(), 'server/data/tool-descriptions.json'),
    path.join(process.cwd(), 'dist-server/server/data/tool-descriptions.json'),
  ];
  for (const p of candidates) {
    if (existsSync(p)) {
      try {
        const raw = JSON.parse(readFileSync(p, 'utf-8'));
        // Strip the _note comment key
        const { _note, ...rest } = raw as DescriptionMap & { _note?: string };
        void _note;
        _cached = rest as DescriptionMap;
        return _cached;
      } catch {
        // Malformed JSON - treat as empty
      }
    }
  }
  _cached = {};
  return _cached;
}

/**
 * Get a human-readable description for the scanner behind a finding.
 * Returns `null` if no mapping exists - the caller should fall back to
 * the finding's own description field or the tool name itself.
 */
export function describeTool(toolName: string | null | undefined): string | null {
  if (!toolName) return null;
  const map = loadDescriptions();
  // Exact match first
  if (map[toolName]) return map[toolName];
  // Strip common suffixes/prefixes and try again
  const stem = toolName
    .toLowerCase()
    .replace(/_v\d+$/, '')
    .replace(/-scanner$/, '_scanner')
    .replace(/\s+/g, '_');
  if (map[stem]) return map[stem];
  // Partial match: find any key that's a prefix of the tool name
  const keys = Object.keys(map).sort((a, b) => b.length - a.length);
  for (const k of keys) {
    if (toolName.toLowerCase().startsWith(k.toLowerCase())) return map[k];
  }
  return null;
}

/** List every known tool_name -> description pair (for AI prompts). */
export function listAllDescriptions(): DescriptionMap {
  return { ...loadDescriptions() };
}
