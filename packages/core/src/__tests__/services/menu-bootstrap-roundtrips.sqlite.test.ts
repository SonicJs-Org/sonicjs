// @ts-nocheck
// Real-SQLite coverage for the *cost* of the menu plugin's bootstrap, not just its result.
//
// `onBoot` runs on every cold isolate, and against a remote D1 each awaited statement is its own
// network round trip. Seeding used to issue one SELECT per system item plus a SELECT and an
// unconditional UPDATE per plugin row — ~51 serial round trips, measured at 11-13s on a preview
// deployment that answered the same route in 0.65s once warm. End-state assertions pass either
// way, so the count is what has to be pinned. The pure-mock suite cannot see any of this (R10).
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../utils/d1-sqlite'
import {
  listMenuItems,
  seedSystemMenuItems,
  upsertSystemItem,
} from '../../plugins/core-plugins/menu-plugin/services/menu-repository'
import { reconcileMenuFromPlugins } from '../../plugins/core-plugins/menu-plugin/services/menu-reconcile'
import { SYSTEM_MENU_ITEMS } from '../../plugins/core-plugins/menu-plugin/services/menu-defaults'

const MENU_TYPE_SQL = `
  INSERT INTO document_types (id, name, display_name, schema, queryable_fields, settings, source, schema_version, is_system, is_active, created_at, updated_at)
  VALUES ('menu_item','menu_item','Menu Item','{}','[]','{}','plugin',1,0,1,1,1)
`

const MENU_FIELDS = [
  { name: 'parent', path: '$.parent', kind: 'scalar', type: 'text', column: 'q_menu_parent' },
  { name: 'visible', path: '$.visible', kind: 'scalar', type: 'boolean', column: 'q_menu_visible' },
  { name: 'source', path: '$.source', kind: 'scalar', type: 'text', column: 'q_menu_source' },
  { name: 'pluginId', path: '$.pluginId', kind: 'scalar', type: 'text', column: 'q_menu_plugin_id' },
]

/**
 * Wrap a TestD1 so every awaited statement is recorded.
 *
 * One entry per thing that would cross the wire: `first`/`all`/`run` on a statement, and the whole
 * of a `batch` as one. `bind` returns a fresh statement, so it has to re-wrap.
 */
function countingD1(inner) {
  const log = []

  const wrapStatement = (stmt) => ({
    bind: (...args) => wrapStatement(stmt.bind(...args)),
    run: async () => {
      log.push('run')
      return stmt.run()
    },
    all: async (...args) => {
      log.push('all')
      return stmt.all(...args)
    },
    first: async (...args) => {
      log.push('first')
      return stmt.first(...args)
    },
    raw: (...args) => stmt.raw(...args),
    execInBatch: () => stmt.execInBatch(),
  })

  return {
    log,
    db: {
      prepare: (sql) => wrapStatement(inner.prepare(sql)),
      batch: async (statements) => {
        log.push(`batch(${statements.length})`)
        return inner.batch(statements)
      },
      raw: inner.raw,
    },
  }
}

function systemSeedInput() {
  return SYSTEM_MENU_ITEMS.map((item) => ({
    slug: item.id,
    data: {
      label: item.label,
      url: item.url,
      icon: item.icon,
      target: item.target,
      isExternal: item.isExternal,
      visible: item.visible,
      parent: item.parent,
      source: item.source,
      pluginId: item.pluginId,
      permissions: [...item.permissions],
      lockedFields: [...item.lockedFields],
    },
    sortOrder: item.sortOrder,
  }))
}

describe('menu bootstrap round trips — real SQLite', () => {
  let db
  let counter

  beforeEach(async () => {
    db = createTestD1()
    db.raw.prepare(MENU_TYPE_SQL).run()
    await db.applyScalarSchema('menu_item', MENU_FIELDS)
    counter = countingD1(db)
  })

  afterEach(() => db.close())

  it('seeds every system item in two round trips, and one on an already-seeded database', async () => {
    const items = systemSeedInput()
    expect(items.length).toBeGreaterThan(1)

    await seedSystemMenuItems(counter.db, items)
    // One SELECT for what already exists, one batch for everything missing — regardless of how
    // many items there are.
    expect(counter.log).toEqual(['all', `batch(${items.length})`])

    const seeded = await listMenuItems(db)
    expect(seeded.map((i) => i.slug).sort()).toEqual(items.map((i) => i.slug).sort())

    counter.log.length = 0
    await seedSystemMenuItems(counter.db, items)
    // Steady state — the cold-isolate case. Nothing is missing, so nothing is written.
    expect(counter.log).toEqual(['all'])
    expect(await listMenuItems(db)).toHaveLength(items.length)
  })

  it('produces the same rows as seeding one item at a time', async () => {
    const items = systemSeedInput()

    for (const item of items) {
      await upsertSystemItem(db, item.slug, item.data, item.sortOrder)
    }
    const oneAtATime = (await listMenuItems(db))
      .map((i) => [i.slug, i.label, i.url, i.icon, i.sortOrder, i.visible, i.source].join('|'))
      .sort()

    const fresh = createTestD1()
    try {
      fresh.raw.prepare(MENU_TYPE_SQL).run()
      await fresh.applyScalarSchema('menu_item', MENU_FIELDS)
      await seedSystemMenuItems(fresh, items)
      const batched = (await listMenuItems(fresh))
        .map((i) => [i.slug, i.label, i.url, i.icon, i.sortOrder, i.visible, i.source].join('|'))
        .sort()
      expect(batched).toEqual(oneAtATime)
    } finally {
      fresh.close()
    }
  })

  it('does nothing to a database the plugin registry already agrees with', async () => {
    await reconcileMenuFromPlugins(counter.db)

    const created = await listMenuItems(db)
    expect(created.length).toBeGreaterThan(0)
    expect(created.every((i) => i.source === 'plugin')).toBe(true)
    // Two independent reads (active plugins, existing rows) plus one batch of inserts.
    expect(counter.log.filter((e) => e.startsWith('batch'))).toHaveLength(1)
    expect(counter.log).toHaveLength(3)

    counter.log.length = 0
    await reconcileMenuFromPlugins(counter.db)
    // Nothing changed, so the batch must not be sent at all. Before this, every boot rewrote
    // every plugin row.
    expect(counter.log.filter((e) => e.startsWith('batch'))).toHaveLength(0)
    expect(counter.log).toHaveLength(2)
    expect(await listMenuItems(db)).toHaveLength(created.length)
  })

  it('still deactivates a plugin row whose plugin left the registry', async () => {
    await reconcileMenuFromPlugins(db)

    const now = Math.floor(Date.now() / 1000)
    const data = JSON.stringify({
      label: 'Ghost',
      url: '/admin/ghost',
      icon: 'puzzle-piece',
      target: '_self',
      isExternal: false,
      visible: true,
      parent: null,
      source: 'plugin',
      pluginId: 'ghost-plugin',
      permissions: [],
      lockedFields: ['url'],
      sortOrder: 900,
    })
    db.raw
      .prepare(
        `INSERT INTO documents (id, root_id, type_id, type_version, version_of_id, version_number,
           is_current_draft, is_published, status, parent_root_id, slug, path, title, zone,
           sort_order, visible, published_at, scheduled_at, expires_at, deleted_at,
           tenant_id, locale, translation_group_id, data, metadata,
           owner_id, created_by, updated_by, created_at, updated_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      )
      .run(
        'ghost', 'ghost', 'menu_item', 1, null, 1,
        1, 0, 'draft', '', 'menu:plugin:ghost-plugin', null, 'Ghost', null,
        900, 1, null, null, null, null,
        'default', 'default', '', data, '{}',
        null, null, null, now, now,
      )

    await reconcileMenuFromPlugins(db)

    const ghost = (await listMenuItems(db)).find((i) => i.slug === 'menu:plugin:ghost-plugin')
    expect(ghost).toBeDefined()
    // listMenuItems hands back the stored 0/1 rather than a boolean.
    expect(ghost.visible).toBeFalsy()
  })
})
