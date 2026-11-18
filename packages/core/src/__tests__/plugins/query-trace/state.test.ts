// @ts-nocheck
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { createTestD1 } from '../../utils/d1-sqlite'
import { PluginService } from '../../../services/plugin-service'
import { getQueryTraceState, invalidateQueryTraceState } from '../../../plugins/core-plugins/query-trace-plugin/state'
import { DEFAULT_QUERY_TRACE_SETTINGS } from '../../../plugins/core-plugins/query-trace-plugin/constants'

const PLUGIN_TYPE_SQL = `
  INSERT INTO document_types (id, name, display_name, schema, queryable_fields, settings, source, schema_version, is_system, is_active, created_at, updated_at)
  VALUES ('plugin','plugin','Plugin','{}','[]','{}','system',1,1,1,1,1)
`

describe('getQueryTraceState (real SQLite)', () => {
  let db, svc
  beforeEach(async () => {
    invalidateQueryTraceState()
    db = createTestD1()
    await db.prepare(PLUGIN_TYPE_SQL).run()
    await db.applyScalarSchema('plugin', [
      { name: 'status', kind: 'scalar', type: 'text', column: 'q_plugin_status' },
      { name: 'category', kind: 'scalar', type: 'text', column: 'q_plugin_category' },
      { name: 'isCore', kind: 'scalar', type: 'integer', column: 'q_plugin_is_core' },
    ])
    svc = new PluginService(db)
  })
  afterEach(() => { db?.close?.(); invalidateQueryTraceState() })

  it('inactive when there is no row', async () => {
    const s = await getQueryTraceState(db)
    expect(s.active).toBe(false)
    expect(s.settings).toEqual(DEFAULT_QUERY_TRACE_SETTINGS)
  })

  it('active with defaults merged under stored settings', async () => {
    await svc.installPlugin({ id: 'query-trace', display_name: 'Query Trace', settings: { visibility: 'all-admins', slowQueryMs: 50 } })
    const s = await getQueryTraceState(db)
    expect(s.active).toBe(true)
    expect(s.settings).toEqual({ ...DEFAULT_QUERY_TRACE_SETTINGS, visibility: 'all-admins', slowQueryMs: 50 })
  })

  it('respects the TTL and re-reads after it', async () => {
    const spy = vi.spyOn(db, 'prepare')
    await getQueryTraceState(db, 1000)
    await getQueryTraceState(db, 1000 + 29_000)
    expect(spy).toHaveBeenCalledTimes(1)
    await getQueryTraceState(db, 1000 + 31_000)
    expect(spy).toHaveBeenCalledTimes(2)
  })

  it('invalidation forces a re-read', async () => {
    await getQueryTraceState(db)
    await db.prepare('SELECT 1').run()
    const spy = vi.spyOn(db, 'prepare')
    invalidateQueryTraceState()
    await getQueryTraceState(db)
    expect(spy).toHaveBeenCalledTimes(1)
  })

  it('stale-after-install regression: install flips to active without waiting for TTL', async () => {
    expect((await getQueryTraceState(db)).active).toBe(false) // primes cache as inactive
    await svc.installPlugin({ id: 'query-trace', display_name: 'Query Trace' })
    expect((await getQueryTraceState(db)).active).toBe(true)
  })

  it('uninstall -> inactive and re-install -> active, immediately', async () => {
    await svc.installPlugin({ id: 'query-trace', display_name: 'Query Trace' })
    expect((await getQueryTraceState(db)).active).toBe(true)
    await svc.uninstallPlugin('query-trace')
    expect((await getQueryTraceState(db)).active).toBe(false)
    await svc.installPlugin({ id: 'query-trace', display_name: 'Query Trace' })
    expect((await getQueryTraceState(db)).active).toBe(true)
  })

  it('activate / deactivate / settings update invalidate', async () => {
    await svc.installPlugin({ id: 'query-trace', display_name: 'Query Trace' })
    await svc.deactivatePlugin('query-trace')
    expect((await getQueryTraceState(db)).active).toBe(false)
    await svc.activatePlugin('query-trace')
    expect((await getQueryTraceState(db)).active).toBe(true)
    await svc.updatePluginSettings('query-trace', { visibility: 'all-admins' })
    expect((await getQueryTraceState(db)).settings.visibility).toBe('all-admins')
  })

  it('DB error => inactive', async () => {
    const broken = { prepare: () => { throw new Error('no such table') } }
    expect((await getQueryTraceState(broken)).active).toBe(false)
  })
})

describe('getQueryTraceState concurrency', () => {
  it('concurrent callers at cold/expired cache share one DB read', async () => {
    invalidateQueryTraceState()
    let calls = 0
    const db = {
      prepare: () => ({
        bind: () => ({
          first: async () => {
            calls++
            await new Promise((r) => setTimeout(r, 5))
            return null
          },
        }),
      }),
    }
    const results = await Promise.all(Array.from({ length: 50 }, () => getQueryTraceState(db, 1000)))
    expect(calls).toBe(1)
    expect(results.every((r) => r.active === false)).toBe(true)
    await getQueryTraceState(db, 1000 + 1000)
    expect(calls).toBe(1)
    invalidateQueryTraceState()
  })
})

describe('getQueryTraceState invalidation race', () => {
  it('a read in flight during invalidate() does not repopulate the cache with its stale value', async () => {
    invalidateQueryTraceState()
    let release!: () => void
    const gate = new Promise<void>((r) => { release = r })
    let status: string | null = 'inactive'
    const mkDb = (afterGate: boolean) => ({
      prepare: () => ({
        bind: () => ({
          first: async () => {
            const seen = status // value at read start
            if (afterGate) await gate
            return seen === 'active' ? { status: 'active', settings: null } : null
          },
        }),
      }),
    })
    const stale = getQueryTraceState(mkDb(true), 1000) // read starts, sees inactive, blocks
    status = 'active'
    invalidateQueryTraceState() // plugin installed mid-flight
    release()
    expect((await stale).active).toBe(false) // the in-flight caller still gets its own value
    // …but the cache must not hold it: next read (same `now`, within TTL) hits the DB and sees active
    expect((await getQueryTraceState(mkDb(false), 1001)).active).toBe(true)
    invalidateQueryTraceState()
  })
})
