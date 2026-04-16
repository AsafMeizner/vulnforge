/**
 * Capability manifest — what server-side AI providers and integrations
 * are exposed to clients, by name + capability only (never secrets).
 *
 * Per-user visibility filtered by RBAC (`ai:use`, `integrations:use`).
 * Admin setting `capability_manifest_enabled` gates the whole feature.
 *
 * Clients see entries like:
 *   ai: [{name:"team-triage", task_tags:["triage","embed"], provider_type:"ollama-proxied"}]
 *   integrations: [{name:"team-jira", type:"jira", actions:["create_ticket"]}]
 *
 * Invocation flows through /api/server/ai/invoke and
 * /api/server/integrations/:name/:action (subsystem B13.10).
 */
import { getDb } from '../db.js';
import { hasPermission } from '../auth/permissions.js';

export interface AiCapability {
  name: string;
  task_tags: string[];
  provider_type: string;
  available: boolean;
}

export interface IntegrationCapability {
  name: string;
  type: string;
  actions: string[];
}

export interface CapabilityManifest {
  ai: AiCapability[];
  integrations: IntegrationCapability[];
  mode: 'desktop' | 'server';
}

function isManifestEnabled(): boolean {
  // Only the server-mode process ever exposes a manifest. Desktop-mode
  // clients always get an empty manifest (they ARE the server themselves).
  if (process.env.VULNFORGE_MODE !== 'server') return false;
  // Admin kill switch via env or settings — default ON for server mode.
  const raw = process.env.VULNFORGE_CAPABILITY_MANIFEST;
  if (raw === 'false' || raw === '0') return false;
  try {
    const db = getDb();
    const stmt = db.prepare(`SELECT value FROM settings WHERE key = 'capability_manifest_enabled'`);
    if (stmt.step()) {
      const v = stmt.get()[0];
      stmt.free();
      if (v === '0' || v === 'false') return false;
    } else {
      stmt.free();
    }
  } catch { /* settings table may not exist yet */ }
  return true;
}

export function getServerCapabilityManifest(user: { user_id: number; role: string }): CapabilityManifest {
  const base: CapabilityManifest = {
    ai: [],
    integrations: [],
    mode: process.env.VULNFORGE_MODE === 'server' ? 'server' : 'desktop',
  };
  if (!isManifestEnabled()) return base;

  // AI providers — only expose those with source='server' and enabled=1.
  if (hasPermission(user.role, 'ai', 'use')) {
    try {
      const db = getDb();
      const stmt = db.prepare(
        `SELECT name, provider, task_tags
         FROM ai_providers
         WHERE enabled = 1
           AND (source IS NULL OR source = 'server')`,
      );
      while (stmt.step()) {
        const row = stmt.get();
        base.ai.push({
          name: String(row[0]),
          task_tags: safeParseArray(row[2] as string),
          provider_type: `${String(row[1] ?? '')}-proxied`,
          available: true,
        });
      }
      stmt.free();
    } catch { /* ai_providers.source column may be missing on older DBs */ }
  }

  // Integrations — expose those with source='server' and enabled=1.
  if (hasPermission(user.role, 'integrations', 'use')) {
    try {
      const db = getDb();
      const stmt = db.prepare(
        `SELECT name, type
         FROM integrations
         WHERE enabled = 1
           AND (source IS NULL OR source = 'server')`,
      );
      while (stmt.step()) {
        const row = stmt.get();
        base.integrations.push({
          name: String(row[0]),
          type: String(row[1]),
          actions: actionsForType(String(row[1])),
        });
      }
      stmt.free();
    } catch { /* integrations.source column may be missing */ }
  }

  return base;
}

function safeParseArray(raw: string | null): string[] {
  if (!raw) return [];
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v.map(String) : [];
  } catch { return []; }
}

function actionsForType(type: string): string[] {
  switch (type) {
    case 'jira':
    case 'linear':
    case 'trello':
    case 'github-issues':
      return ['create_ticket', 'update_ticket', 'comment'];
    case 'slack':
      return ['send_notification'];
    default:
      return [];
  }
}
