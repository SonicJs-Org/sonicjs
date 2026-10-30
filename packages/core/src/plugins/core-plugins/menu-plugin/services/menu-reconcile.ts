import { D1Database, D1PreparedStatement } from '@cloudflare/workers-types'
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

interface MenuRow {
  id: string
  slug: string
  data: string
  visible: number
}

interface MenuRowData {
  source?: string
  pluginId?: string
  url?: string
  visible?: unknown
}

/**
 * Every `menu_item` row, in one query.
 *
 * Both halves of the reconcile used to run their own SELECT — the upsert one *per plugin*, which
 * on a remote D1 is one round trip each. One snapshot answers both, and nothing between them
 * writes, so the end state is unchanged.
 */
async function fetchMenuRows(db: D1Database): Promise<MenuRow[]> {
  const rows = await db
    .prepare(
      `SELECT id, slug, data, visible FROM documents
       WHERE type_id = 'menu_item' AND tenant_id = 'default'
         AND is_current_draft = 1 AND deleted_at IS NULL`,
    )
    .all<MenuRow>()
  return rows.results ?? []
}

function parseRowData(raw: string): MenuRowData | null {
  try {
    const parsed = JSON.parse(raw)
    return parsed && typeof parsed === 'object' ? (parsed as MenuRowData) : null
  } catch {
    return null
  }
}

/** `data.visible` is written as a JSON boolean on insert and as 1/0 by `json_set` on update. */
function isVisibleFlag(value: unknown): boolean {
  return value === true || value === 1
}

function buildPluginRowUpdate(
  db: D1Database,
  id: string,
  entry: ActivePluginEntry,
  visible: boolean,
  now: number,
): D1PreparedStatement {
  return db
    .prepare(
      `UPDATE documents
       SET data = json_set(data, '$.url', ?, '$.pluginId', ?, '$.visible', ?),
           visible = ?,
           updated_at = ?
       WHERE id = ? AND tenant_id = 'default'`,
    )
    .bind(entry.url, entry.pluginId, visible ? 1 : 0, visible ? 1 : 0, now, id)
}

function buildPluginRowInsert(
  db: D1Database,
  slug: string,
  entry: ActivePluginEntry,
  visible: boolean,
  now: number,
): D1PreparedStatement {
  const id = nanoid()
  const data = JSON.stringify({
    label: entry.label,
    url: entry.url,
    icon: entry.icon,
    target: '_self',
    isExternal: false,
    visible,
    parent: null,
    source: 'plugin',
    pluginId: entry.pluginId,
    permissions: [],
    lockedFields: ['url'],
    sortOrder: entry.sortOrder,
  })

  // 30 columns — matches documents INSERT in DocumentsService.create (R5)
  return db
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
      entry.sortOrder, visible ? 1 : 0, null, null, null, null,
      'default', 'default', '', data, '{}',
      null, null, null, now, now,
    )
}

function buildDeactivate(db: D1Database, id: string, now: number): D1PreparedStatement {
  return db
    .prepare(
      `UPDATE documents
       SET data = json_set(data, '$.visible', 0), visible = 0, updated_at = ?
       WHERE id = ? AND tenant_id = 'default'`,
    )
    .bind(now, id)
}

async function fetchActivePluginIds(db: D1Database): Promise<Set<string>> {
  try {
    const rows = await db
      .prepare(
        `SELECT slug FROM documents
         WHERE type_id = 'plugin' AND tenant_id = 'default'
           AND is_current_draft = 1 AND deleted_at IS NULL
           AND json_extract(data, '$.status') = 'active'`,
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

    const now = Math.floor(Date.now() / 1000)

    // Only plugins explicitly active in DB get visible=true on first insert.
    // Plugins not yet in DB (never installed) default to visible=false.
    // Both reads are independent, so they cost one round trip rather than two.
    const [activeIds, rows] = await Promise.all([fetchActivePluginIds(db), fetchMenuRows(db)])

    const bySlug = new Map(rows.map((row) => [row.slug, row]))
    const statements: D1PreparedStatement[] = []
    const reconciledSlugs = new Set<string>()

    // Upsert all registry plugin entries; visible depends on active status
    for (const [pluginId, entry] of byPluginId) {
      const slug = `menu:plugin:${pluginId}`
      const visible = activeIds.has(pluginId)
      reconciledSlugs.add(slug)

      const existing = bySlug.get(slug)
      if (!existing) {
        statements.push(buildPluginRowInsert(db, slug, entry, visible, now))
        continue
      }

      // Skip rows the UPDATE would not change. This runs on every cold isolate and the registry
      // is almost always already in sync, so without this the batch rewrites every plugin row on
      // every boot for nothing.
      const current = parseRowData(existing.data)
      if (
        current?.url === entry.url &&
        current?.pluginId === entry.pluginId &&
        isVisibleFlag(current?.visible) === visible &&
        existing.visible === (visible ? 1 : 0)
      ) {
        continue
      }

      statements.push(buildPluginRowUpdate(db, existing.id, entry, visible, now))
    }

    // Deactivate rows whose plugin is inactive or removed from registry. Read off the same
    // snapshot as the loop above: a row that loop handled is already being driven to the right
    // visibility (0 for an inactive plugin), so it needs no second statement.
    for (const row of rows) {
      if (reconciledSlugs.has(row.slug)) continue

      const parsed = parseRowData(row.data)
      if (parsed?.source !== 'plugin') continue
      if (typeof parsed.pluginId !== 'string' || activeIds.has(parsed.pluginId)) continue
      if (row.visible === 0 && !isVisibleFlag(parsed.visible)) continue

      statements.push(buildDeactivate(db, row.id, now))
    }

    if (statements.length > 0) {
      await db.batch(statements)
    }
  } catch {
    // DB may not be ready at bootstrap; swallow silently
  }
}
