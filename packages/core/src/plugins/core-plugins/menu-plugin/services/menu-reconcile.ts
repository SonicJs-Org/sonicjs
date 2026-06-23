import { D1Database } from '@cloudflare/workers-types'
import { nanoid } from 'nanoid'
import { getPluginMenu, type PluginMenuEntry } from '../../../../services/plugin-menu-singleton'
import { PLUGIN_REGISTRY, type PluginRegistryEntry } from '../../../../plugins/manifest-registry'

interface ActivePluginEntry {
  pluginId: string
  label: string
  url: string
  icon: string
  sortOrder: number
}

async function upsertPluginRow(
  db: D1Database,
  slug: string,
  entry: ActivePluginEntry,
): Promise<void> {
  const now = Math.floor(Date.now() / 1000)

  const existing = await db
    .prepare(
      `SELECT id FROM documents
       WHERE slug = ? AND type_id = 'menu_item' AND tenant_id = 'default'
         AND is_current_draft = 1 AND deleted_at IS NULL`,
    )
    .bind(slug)
    .first<{ id: string }>()

  if (existing) {
    await db
      .prepare(
        `UPDATE documents
         SET data = json_set(data, '$.url', ?, '$.pluginId', ?),
             updated_at = ?
         WHERE id = ? AND tenant_id = 'default'`,
      )
      .bind(entry.url, entry.pluginId, now, existing.id)
      .run()
    return
  }

  const id = nanoid()
  const data = JSON.stringify({
    label: entry.label,
    url: entry.url,
    icon: entry.icon,
    target: '_self',
    isExternal: false,
    visible: true,
    parent: null,
    source: 'plugin',
    pluginId: entry.pluginId,
    permissions: [],
    lockedFields: ['url', 'parent'],
    sortOrder: entry.sortOrder,
  })

  // 30 columns — matches documents INSERT in DocumentsService.create (R5)
  await db
    .prepare(
      `INSERT INTO documents (id, root_id, type_id, type_version, version_of_id, version_number,
         is_current_draft, is_published, status, parent_root_id, slug, path, title, zone,
         sort_order, visible, published_at, scheduled_at, expires_at, deleted_at,
         tenant_id, locale, translation_group_id, data, metadata,
         owner_id, created_by, updated_by, created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    )
    .bind(
      id, id, 'menu_item', 1, null, 1,
      1, 0, 'draft', '', slug, null, entry.label, null,
      entry.sortOrder, 1, null, null, null, null,
      'default', 'default', '', data, '{}',
      null, null, null, now, now,
    )
    .run()
}

async function deactivateStalePluginRows(
  db: D1Database,
  activePluginIds: Set<string>,
): Promise<void> {
  const now = Math.floor(Date.now() / 1000)

  const rows = await db
    .prepare(
      `SELECT id, data FROM documents
       WHERE type_id = 'menu_item' AND tenant_id = 'default'
         AND is_current_draft = 1 AND deleted_at IS NULL
         AND json_extract(data, '$.source') = 'plugin'`,
    )
    .all<{ id: string; data: string }>()

  const stale = (rows.results ?? []).filter((row) => {
    let pluginId: string | undefined
    try {
      pluginId = JSON.parse(row.data)?.pluginId as string | undefined
    } catch {
      return false
    }
    return pluginId !== undefined && !activePluginIds.has(pluginId)
  })

  if (stale.length === 0) return

  await db.batch(
    stale.map((row) =>
      db
        .prepare(
          `UPDATE documents
           SET data = json_set(data, '$.visible', 0), updated_at = ?
           WHERE id = ? AND tenant_id = 'default'`,
        )
        .bind(now, row.id),
    ),
  )
}

async function fetchInactivePluginIds(db: D1Database): Promise<Set<string>> {
  try {
    const rows = await db
      .prepare(
        `SELECT slug FROM documents
         WHERE type_id = 'plugin' AND tenant_id = 'default'
           AND is_current_draft = 1 AND deleted_at IS NULL
           AND json_extract(data, '$.status') = 'inactive'`,
      )
      .all<{ slug: string }>()
    return new Set((rows.results ?? []).map((r) => r.slug))
  } catch {
    return new Set()
  }
}

export async function reconcileMenuFromPlugins(db: D1Database): Promise<void> {
  try {
    // Source A: code-declared plugins via definePlugin({ menu: [...] })
    const singletonEntries = getPluginMenu()

    // Source B: manifest-registered plugins with adminMenu
    const manifestEntries = (Object.values(PLUGIN_REGISTRY) as PluginRegistryEntry[]).filter(
      (p): p is PluginRegistryEntry & { adminMenu: NonNullable<PluginRegistryEntry['adminMenu']> } =>
        p.adminMenu !== null,
    )

    // Merge into a map keyed by pluginId; manifest entries provide the base,
    // singleton entries (code-declared) win if both define the same pluginId.
    const byPluginId = new Map<string, ActivePluginEntry>()

    // Index manifest entries first (lower priority)
    manifestEntries.forEach((p: PluginRegistryEntry, idx: number) => {
      const menu = p.adminMenu!
      byPluginId.set(p.id, {
        pluginId: p.id,
        label: menu.label,
        url: menu.path,
        icon: menu.icon,
        sortOrder: 100 + idx * 10,
      })
    })

    // Singleton entries override (higher priority — code-declared wins)
    singletonEntries.forEach((entry: PluginMenuEntry, idx: number) => {
      // Derive pluginId from path: last path segment after /admin/plugins/<id>
      // or fall back to a slugified label. The slug uniqueness is enforced by
      // the caller using `menu:plugin:<pluginId>` so we do the same derivation.
      const pathParts = entry.path.replace(/\/$/, '').split('/')
      const pluginId =
        pathParts[pathParts.length - 1] ||
        entry.label.toLowerCase().replace(/\s+/g, '-')

      byPluginId.set(pluginId, {
        pluginId,
        label: entry.label,
        url: entry.path,
        icon: entry.icon ?? 'puzzle-piece',
        sortOrder: 100 + idx * 10,
      })
    })

    // Exclude plugins explicitly disabled in the DB — their menu rows will be
    // hidden by deactivateStalePluginRows below (same path as removed plugins).
    const inactiveIds = await fetchInactivePluginIds(db)
    for (const id of inactiveIds) {
      byPluginId.delete(id)
    }

    // Upsert each active plugin entry
    for (const [pluginId, entry] of byPluginId) {
      const slug = `menu:plugin:${pluginId}`
      await upsertPluginRow(db, slug, entry)
    }

    // Deactivate rows whose plugin is no longer active (removed or disabled)
    await deactivateStalePluginRows(db, new Set(byPluginId.keys()))
  } catch {
    // DB may not be ready at bootstrap; swallow silently
  }
}
