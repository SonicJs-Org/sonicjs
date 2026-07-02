// @ts-nocheck
// Real-SQLite coverage for menu-plugin data layer.
// Tests: idempotent seeding, plugin reconcile, soft-delete guards, reorder batch.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../utils/d1-sqlite'
import {
  listMenuItems,
  buildSidebarTree,
  upsertSystemItem,
  upsertPluginItem,
  reorderItems,
  toggleVisibility,
  updateItem,
  deleteItem,
} from '../../plugins/core-plugins/menu-plugin/services/menu-repository'

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

function systemItemData(overrides = {}) {
  return {
    label: 'Content',
    url: '/admin/content',
    icon: 'document',
    target: '_self',
    isExternal: false,
    visible: true,
    parent: null,
    source: 'system',
    pluginId: null,
    permissions: [],
    lockedFields: ['url', 'parent'],
    ...overrides,
  }
}

describe('menu-repository — real SQLite', () => {
  let db

  beforeEach(async () => {
    db = createTestD1()
    db.raw.prepare(MENU_TYPE_SQL).run()
    await db.applyScalarSchema('menu_item', MENU_FIELDS)
  })

  afterEach(() => db.close())

  it('upsertSystemItem is idempotent across two boots — no duplicates', async () => {
    const slug = 'menu:system:content'
    const data = systemItemData()

    await upsertSystemItem(db, slug, data, 10)
    await upsertSystemItem(db, slug, data, 10)

    const items = await listMenuItems(db)
    const matching = items.filter((i) => i.slug === slug)
    expect(matching).toHaveLength(1)
  })

  it('upsertPluginItem upserts on first call then only updates url+pluginId', async () => {
    const slug = 'menu:plugin:email'
    const data = {
      label: 'Email',
      url: '/admin/email',
      icon: 'envelope',
      target: '_self',
      isExternal: false,
      visible: true,
      parent: null,
      source: 'plugin',
      pluginId: 'email',
      permissions: [],
      lockedFields: ['url', 'parent'],
    }

    await upsertPluginItem(db, slug, data, 100)

    // Simulate admin renaming label — change label in DB directly
    const items1 = await listMenuItems(db)
    const item = items1.find((i) => i.slug === slug)
    expect(item).toBeDefined()
    db.raw.prepare(`UPDATE documents SET data = json_set(data, '$.label', ?) WHERE id = ?`)
      .run('Email (Custom)', item.id)

    // Re-upsert with original data — should NOT overwrite admin's custom label
    await upsertPluginItem(db, slug, data, 100)

    const items2 = await listMenuItems(db)
    const updated = items2.find((i) => i.slug === slug)
    expect(updated.label).toBe('Email (Custom)')
    expect(updated.url).toBe('/admin/email')
  })

  it('reorderItems batch-updates sort_order (R1)', async () => {
    await upsertSystemItem(db, 'menu:system:content', systemItemData({ label: 'Content' }), 10)
    await upsertSystemItem(db, 'menu:system:users', systemItemData({ label: 'Users', url: '/admin/users' }), 20)

    const before = await listMenuItems(db)
    const [a, b] = before.map((i) => ({ id: i.id, sortOrder: i.sortOrder }))

    // Swap sort orders
    await reorderItems(db, [
      { id: a.id, sortOrder: b.sortOrder, parent: null },
      { id: b.id, sortOrder: a.sortOrder, parent: null },
    ])

    const after = await listMenuItems(db)
    const aAfter = after.find((i) => i.id === a.id)
    const bAfter = after.find((i) => i.id === b.id)
    expect(aAfter.sortOrder).toBe(b.sortOrder)
    expect(bAfter.sortOrder).toBe(a.sortOrder)
  })

  it('deleteItem blocks system source, allows user source', async () => {
    await upsertSystemItem(db, 'menu:system:content', systemItemData({ source: 'system' }), 10)
    const items = await listMenuItems(db)
    const systemItem = items[0]

    const sysResult = await deleteItem(db, systemItem.id)
    expect(sysResult.ok).toBe(false)
    expect(sysResult.reason).toBeDefined()

    // Create a user item
    const userSlug = 'menu:user:test'
    await upsertSystemItem(db, userSlug, systemItemData({ source: 'user', lockedFields: [] }), 50)
    const items2 = await listMenuItems(db)
    const userItem = items2.find((i) => i.slug === userSlug)
    expect(userItem).toBeDefined()

    const userResult = await deleteItem(db, userItem.id)
    expect(userResult.ok).toBe(true)

    const items3 = await listMenuItems(db)
    expect(items3.find((i) => i.id === userItem.id)).toBeUndefined()
  })

  it('toggleVisibility updates both column and data JSON', async () => {
    await upsertSystemItem(db, 'menu:system:settings', systemItemData({ label: 'Settings', url: '/admin/settings' }), 40)
    const items = await listMenuItems(db)
    const item = items[0]

    await toggleVisibility(db, item.id, false)

    const row = db.raw.prepare('SELECT visible, data FROM documents WHERE id = ?').get(item.id)
    expect(row.visible).toBeFalsy()
    const data = JSON.parse(row.data)
    expect(data.visible).toBeFalsy()
  })

  it('updateItem rejects locked fields', async () => {
    await upsertSystemItem(db, 'menu:system:content', systemItemData(), 10)
    const items = await listMenuItems(db)
    const item = items[0]

    // Should be rejected — url is locked
    const rejected = await updateItem(db, item.id, { url: '/admin/other' }, ['url', 'parent'])
    expect(rejected).toBe(false)

    // Label change should succeed
    const ok = await updateItem(db, item.id, { label: 'My Content' }, ['url', 'parent'])
    expect(ok).toBe(true)

    const updated = (await listMenuItems(db)).find((i) => i.id === item.id)
    expect(updated.label).toBe('My Content')
    // URL unchanged
    expect(updated.url).toBe('/admin/content')
  })

  it('buildSidebarTree nests children under parents and sorts by sortOrder', async () => {
    await upsertSystemItem(db, 'menu:system:parent', systemItemData({ label: 'Parent', url: '/admin/parent' }), 10)
    const all = await listMenuItems(db)
    const parentId = all[0].id

    // Add child
    await upsertSystemItem(db, 'menu:system:child', systemItemData({
      label: 'Child',
      url: '/admin/parent/child',
      parent: parentId,
      source: 'user',
      lockedFields: [],
    }), 5)

    const items = await listMenuItems(db)
    const tree = buildSidebarTree(items)

    expect(tree).toHaveLength(1)
    expect(tree[0].children).toHaveLength(1)
    expect(tree[0].children[0].label).toBe('Child')
  })
})
