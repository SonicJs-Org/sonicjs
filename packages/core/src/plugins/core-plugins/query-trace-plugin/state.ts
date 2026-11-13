import type { D1Database } from '@cloudflare/workers-types'
import {
  DEFAULT_QUERY_TRACE_SETTINGS,
  QUERY_TRACE_PLUGIN_ID,
  QUERY_TRACE_STATE_TTL_MS,
  type QueryTraceSettings,
} from './constants'

export interface QueryTraceState {
  active: boolean
  settings: QueryTraceSettings
  fetchedAt: number
}

let cached: QueryTraceState | null = null

/** Drop the per-isolate cache. Call after install/uninstall/activate/deactivate/settings changes. */
export function invalidateQueryTraceState(): void {
  cached = null
}

function inactive(now: number): QueryTraceState {
  return { active: false, settings: { ...DEFAULT_QUERY_TRACE_SETTINGS }, fetchedAt: now }
}

function parseSettings(raw: unknown): QueryTraceSettings {
  let stored: Record<string, unknown> = {}
  if (typeof raw === 'string' && raw) {
    try {
      const parsed = JSON.parse(raw)
      if (parsed && typeof parsed === 'object') stored = parsed
    } catch {
      /* fall back to defaults */
    }
  } else if (raw && typeof raw === 'object') {
    stored = raw as Record<string, unknown>
  }
  const merged = { ...DEFAULT_QUERY_TRACE_SETTINGS, ...stored } as QueryTraceSettings
  // Clamp to sane bounds so a bad stored value can't disable the per-request cap.
  merged.maxEntries = Math.min(5000, Math.max(100, Number(merged.maxEntries) || DEFAULT_QUERY_TRACE_SETTINGS.maxEntries))
  merged.warnQueryMs = Number(merged.warnQueryMs) || DEFAULT_QUERY_TRACE_SETTINGS.warnQueryMs
  merged.slowQueryMs = Number(merged.slowQueryMs) || DEFAULT_QUERY_TRACE_SETTINGS.slowQueryMs
  if (merged.visibility !== 'all-admins') merged.visibility = 'opt-in'
  return merged
}

/**
 * One cheap read of {active, settings}, cached for QUERY_TRACE_STATE_TTL_MS per isolate.
 * Must be called with the RAW (unwrapped) DB so it is never traced. DB errors => inactive.
 */
export async function getQueryTraceState(db: D1Database, now: number = Date.now()): Promise<QueryTraceState> {
  if (cached && now - cached.fetchedAt < QUERY_TRACE_STATE_TTL_MS) return cached
  let next: QueryTraceState
  try {
    const row = (await db
      .prepare(
        `SELECT json_extract(data,'$.status') AS status, json_extract(data,'$.settings') AS settings
         FROM documents WHERE slug = ? AND type_id = 'plugin' AND tenant_id = 'default'
           AND is_current_draft = 1 AND deleted_at IS NULL`
      )
      .bind(QUERY_TRACE_PLUGIN_ID)
      .first()) as { status?: string; settings?: unknown } | null
    next =
      row?.status === 'active'
        ? { active: true, settings: parseSettings(row.settings), fetchedAt: now }
        : inactive(now)
  } catch {
    next = inactive(now)
  }
  cached = next
  return next
}
