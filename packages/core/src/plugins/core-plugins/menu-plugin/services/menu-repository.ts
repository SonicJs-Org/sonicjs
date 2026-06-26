import { D1Database } from '@cloudflare/workers-types'
import { nanoid } from 'nanoid'

export interface MenuItemData {
  label: string
  url: string
  icon: string
  target: '_self' | '_blank'
  isExternal: boolean
  visible: boolean
  parent: string | null
  source: 'system' | 'plugin' | 'user'
  pluginId: string | null
  permissions: string[]
  lockedFields: ('url')[]
}

export interface MenuItem extends MenuItemData {
  id: string
  slug: string
  sortOrder: number
  tenantId: string
}

export interface SidebarItem {
  id: string
  label: string
  url: string
  icon: string
  target: '_self' | '_blank'
  isExternal: boolean
  visible: boolean
  source: string
  sortOrder: number
  children: SidebarItem[]
}

export async function listMenuItems(
  db: D1Database,
  opts?: { source?: string }
): Promise<MenuItem[]> {
  try {
    let sql = `
      SELECT id, slug, sort_order, data
      FROM documents
      WHERE type_id = 'menu_item'
        AND tenant_id = 'default'
        AND is_current_draft = 1
        AND deleted_at IS NULL
    `
    const binds: unknown[] = []

    if (opts?.source) {
      sql += ` AND q_menu_source = ?`
      binds.push(opts.source)
    }

    sql += ` ORDER BY sort_order ASC`

    const stmt = db.prepare(sql)
    const result = await (binds.length ? stmt.bind(...binds) : stmt).all<{
      id: string
      slug: string
      sort_order: number
      data: string
    }>()

    return (result.results ?? []).map((row) => {
      const data: MenuItemData = JSON.parse(row.data)
      return {
        ...data,
        id: row.id,
        slug: row.slug,
        sortOrder: row.sort_order,
        tenantId: 'default',
      }
    })
  } catch {
    return []
  }
}

/**
 * Returns a map of pluginId → 'active'|'inactive' for the given plugin IDs.
 * Uses the same query as PluginService.getAllPlugins — reads all plugin documents
 * and maps slug → status, defaulting unrecognised slugs to 'active'.
 */
export async function fetchPluginStatuses(
  db: D1Database,
  pluginIds: string[],
): Promise<Record<string, 'active' | 'inactive'>> {
  if (pluginIds.length === 0) return {}
  try {
    const rows = await db
      .prepare(
        `SELECT slug, json_extract(data, '$.status') AS status
         FROM documents
         WHERE type_id = 'plugin' AND tenant_id = 'default'
           AND is_current_draft = 1 AND deleted_at IS NULL`,
      )
      .all<{ slug: string; status: string | null }>()

    const statusMap = new Map<string, string>()
    for (const row of rows.results ?? []) {
      statusMap.set(row.slug, row.status ?? 'inactive')
    }

    const result: Record<string, 'active' | 'inactive'> = {}
    for (const id of pluginIds) {
      const s = statusMap.get(id)
      // Only explicitly active in DB → enabled; uninstalled/inactive → disabled
      result[id] = s === 'active' ? 'active' : 'inactive'
    }
    return result
  } catch {
    return {}
  }
}

export function buildSidebarTree(items: MenuItem[]): SidebarItem[] {
  const visible = items.filter((i) => i.visible)
  visible.sort((a, b) => a.sortOrder - b.sortOrder)

  const byId = new Map<string, SidebarItem>()
  const roots: SidebarItem[] = []

  for (const item of visible) {
    byId.set(item.id, {
      id: item.id,
      label: item.label,
      url: item.url,
      icon: item.icon,
      target: item.target,
      isExternal: item.isExternal,
      visible: item.visible,
      source: item.source,
      sortOrder: item.sortOrder,
      children: [],
    })
  }

  for (const item of visible) {
    const node = byId.get(item.id)!
    if (item.parent && byId.has(item.parent)) {
      byId.get(item.parent)!.children.push(node)
    } else {
      roots.push(node)
    }
  }

  for (const node of byId.values()) {
    node.children.sort((a, b) => a.sortOrder - b.sortOrder)
  }

  return roots
}

export async function upsertSystemItem(
  db: D1Database,
  slug: string,
  data: MenuItemData,
  sortOrder: number
): Promise<void> {
  const now = Math.floor(Date.now() / 1000)

  const existing = await db
    .prepare(
      `SELECT id FROM documents WHERE slug = ? AND type_id = 'menu_item' AND tenant_id = 'default' AND is_current_draft = 1 AND deleted_at IS NULL`
    )
    .bind(slug)
    .first<{ id: string }>()

  if (existing) {
    return
  }

  const id = nanoid()

  await db
    .prepare(
      `INSERT INTO documents (
        id, root_id, type_id, type_version, version_of_id, version_number,
        is_current_draft, is_published, status, parent_root_id,
        slug, path, title, zone, sort_order, visible,
        published_at, scheduled_at, expires_at, deleted_at,
        tenant_id, locale, translation_group_id,
        data, metadata, owner_id, created_by, updated_by, created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?,
        ?, ?, ?, ?, ?, ?, ?
      )`
    )
    .bind(
      id,                       // id
      id,                       // root_id
      'menu_item',              // type_id
      1,                        // type_version
      null,                     // version_of_id
      1,                        // version_number
      1,                        // is_current_draft
      1,                        // is_published
      'published',              // status
      '',                       // parent_root_id
      slug,                     // slug
      null,                     // path
      data.label,               // title
      null,                     // zone
      sortOrder,                // sort_order
      data.visible ? 1 : 0,    // visible
      now,                      // published_at
      null,                     // scheduled_at
      null,                     // expires_at
      null,                     // deleted_at
      'default',                // tenant_id
      'default',                // locale
      '',                       // translation_group_id
      JSON.stringify(data),     // data
      '{}',                     // metadata
      null,                     // owner_id
      'system',                 // created_by
      'system',                 // updated_by
      now,                      // created_at
      now                       // updated_at
    )
    .run()
}

export async function upsertPluginItem(
  db: D1Database,
  slug: string,
  data: MenuItemData,
  sortOrder: number
): Promise<void> {
  const now = Math.floor(Date.now() / 1000)

  const existing = await db
    .prepare(
      `SELECT id, data FROM documents WHERE slug = ? AND type_id = 'menu_item' AND tenant_id = 'default' AND is_current_draft = 1 AND deleted_at IS NULL`
    )
    .bind(slug)
    .first<{ id: string; data: string }>()

  if (existing) {
    const currentData: MenuItemData = JSON.parse(existing.data)
    const updatedData: MenuItemData = {
      ...currentData,
      url: data.url,
      pluginId: data.pluginId,
    }

    await db
      .prepare(
        `UPDATE documents SET data = ?, updated_at = ? WHERE id = ? AND tenant_id = 'default'`
      )
      .bind(JSON.stringify(updatedData), now, existing.id)
      .run()

    return
  }

  const id = nanoid()

  await db
    .prepare(
      `INSERT INTO documents (
        id, root_id, type_id, type_version, version_of_id, version_number,
        is_current_draft, is_published, status, parent_root_id,
        slug, path, title, zone, sort_order, visible,
        published_at, scheduled_at, expires_at, deleted_at,
        tenant_id, locale, translation_group_id,
        data, metadata, owner_id, created_by, updated_by, created_at, updated_at
      ) VALUES (
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?,
        ?, ?, ?, ?, ?, ?, ?
      )`
    )
    .bind(
      id,                       // id
      id,                       // root_id
      'menu_item',              // type_id
      1,                        // type_version
      null,                     // version_of_id
      1,                        // version_number
      1,                        // is_current_draft
      1,                        // is_published
      'published',              // status
      '',                       // parent_root_id
      slug,                     // slug
      null,                     // path
      data.label,               // title
      null,                     // zone
      sortOrder,                // sort_order
      data.visible ? 1 : 0,    // visible
      now,                      // published_at
      null,                     // scheduled_at
      null,                     // expires_at
      null,                     // deleted_at
      'default',                // tenant_id
      'default',                // locale
      '',                       // translation_group_id
      JSON.stringify(data),     // data
      '{}',                     // metadata
      null,                     // owner_id
      'system',                 // created_by
      'system',                 // updated_by
      now,                      // created_at
      now                       // updated_at
    )
    .run()
}

export async function reorderItems(
  db: D1Database,
  items: Array<{ id: string; sortOrder: number; parent: string | null }>
): Promise<void> {
  if (items.length === 0) return

  const now = Math.floor(Date.now() / 1000)

  const stmts = items.map((item) =>
    db
      .prepare(
        `UPDATE documents SET
          sort_order = ?,
          data = json_set(data, '$.parent', ?),
          updated_at = ?
        WHERE id = ? AND tenant_id = 'default'`
      )
      .bind(item.sortOrder, item.parent ?? null, now, item.id)
  )

  await db.batch(stmts)
}

export async function toggleVisibility(
  db: D1Database,
  id: string,
  visible: boolean
): Promise<void> {
  const now = Math.floor(Date.now() / 1000)
  const visInt = visible ? 1 : 0

  await db
    .prepare(
      `UPDATE documents SET
        data = json_set(data, '$.visible', ?),
        visible = ?,
        updated_at = ?
      WHERE id = ? AND tenant_id = 'default'`
    )
    .bind(visInt, visInt, now, id)
    .run()
}

export async function updateItem(
  db: D1Database,
  id: string,
  changes: Partial<
    Pick<
      MenuItemData,
      'label' | 'icon' | 'target' | 'permissions' | 'url' | 'parent' | 'visible'
    > & { sortOrder?: number }
  >,
  lockedFields: string[]
): Promise<boolean> {
  // parent is always editable — admins control layout regardless of source
  const lockedKeys = new Set(lockedFields.filter(f => f !== 'parent'))

  for (const key of Object.keys(changes)) {
    if (lockedKeys.has(key)) {
      return false
    }
  }

  const now = Math.floor(Date.now() / 1000)

  const jsonSetParts: string[] = []
  const binds: unknown[] = []

  const dataFields = ['label', 'icon', 'target', 'permissions', 'url', 'parent', 'visible'] as const

  for (const field of dataFields) {
    if (field in changes) {
      jsonSetParts.push(`'$.${field}'`, '?')
      binds.push(
        field === 'permissions'
          ? JSON.stringify(changes[field])
          : changes[field] ?? null
      )
    }
  }

  const setParts: string[] = []

  if (jsonSetParts.length > 0) {
    setParts.push(`data = json_set(data, ${jsonSetParts.join(', ')})`)
  }

  if ('sortOrder' in changes && changes.sortOrder !== undefined) {
    setParts.push(`sort_order = ?`)
    binds.push(changes.sortOrder)
  }

  if ('visible' in changes && changes.visible !== undefined) {
    setParts.push(`visible = ?`)
    binds.push(changes.visible ? 1 : 0)
  }

  if (setParts.length === 0) {
    return true
  }

  setParts.push(`updated_at = ?`)
  binds.push(now)
  binds.push(id)

  const sql = `UPDATE documents SET ${setParts.join(', ')} WHERE id = ? AND tenant_id = 'default'`

  await db.prepare(sql).bind(...binds).run()

  return true
}

export async function deleteItem(
  db: D1Database,
  id: string
): Promise<{ ok: boolean; reason?: string }> {
  try {
    const row = await db
      .prepare(
        `SELECT data FROM documents WHERE id = ? AND tenant_id = 'default' AND is_current_draft = 1 AND deleted_at IS NULL`
      )
      .bind(id)
      .first<{ data: string }>()

    if (!row) {
      return { ok: false, reason: 'Item not found' }
    }

    const data: MenuItemData = JSON.parse(row.data)

    if (data.source === 'system' || data.source === 'plugin') {
      return { ok: false, reason: 'Cannot delete system or plugin items' }
    }

    const now = Math.floor(Date.now() / 1000)

    await db
      .prepare(
        `UPDATE documents SET deleted_at = ? WHERE id = ? AND tenant_id = 'default'`
      )
      .bind(now, id)
      .run()

    return { ok: true }
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : 'Unknown error' }
  }
}
