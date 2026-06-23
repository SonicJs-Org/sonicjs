import { Hono } from 'hono'
import type { Bindings, Variables } from '../../../../app'
import { requireAuth, requireRole } from '../../../../middleware'
import { escapeHtml } from '../../../../utils/sanitize'
import {
  listMenuItems,
  buildSidebarTree,
  updateItem,
  deleteItem,
  toggleVisibility,
  reorderItems,
  fetchPluginStatuses,
} from '../services/menu-repository'
import { nanoid } from 'nanoid'
import { D1Database } from '@cloudflare/workers-types'
// Template imports (will be created):
import { renderMenuListPage } from '../templates/admin-menu-list.template'
import { renderMenuFormPage } from '../templates/admin-menu-form.template'

export const adminMenuRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

adminMenuRoutes.use('*', requireAuth())
adminMenuRoutes.use('*', requireRole(['admin']))

adminMenuRoutes.get('/', async (c) => {
  const db = c.env.DB
  const user = c.get('user')
  const items = await listMenuItems(db)
  const tree = buildSidebarTree(items)
  const pluginIds = [...new Set(items.filter(i => i.pluginId).map(i => i.pluginId as string))]
  const pluginStatuses = await fetchPluginStatuses(db, pluginIds)
  return c.html(renderMenuListPage({
    items,
    tree,
    pluginStatuses,
    user,
    currentPath: '/admin/menu',
    version: c.get('appVersion'),
    dynamicMenuItems: c.get('pluginMenuItems'),
    message: c.req.query('message'),
  }))
})

adminMenuRoutes.get('/new', async (c) => {
  const db = c.env.DB
  const topLevelItems = await listMenuItems(db)
  return c.html(renderMenuFormPage({
    item: null,
    topLevelItems: topLevelItems.filter(i => !i.parent),
    user: c.get('user'),
    currentPath: '/admin/menu',
    version: c.get('appVersion'),
    dynamicMenuItems: c.get('pluginMenuItems'),
  }))
})

adminMenuRoutes.get('/:id', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')
  const items = await listMenuItems(db)
  const item = items.find(i => i.id === id)
  if (!item) return c.notFound()
  const topLevelItems = items.filter(i => !i.parent && i.id !== id)
  return c.html(renderMenuFormPage({
    item,
    topLevelItems,
    user: c.get('user'),
    currentPath: '/admin/menu',
    version: c.get('appVersion'),
    dynamicMenuItems: c.get('pluginMenuItems'),
  }))
})

adminMenuRoutes.post('/', async (c) => {
  const db = c.env.DB
  const form = await c.req.formData()
  const label = String(form.get('label') ?? '').trim()
  const url = String(form.get('url') ?? '').trim()
  const icon = String(form.get('icon') ?? 'link').trim()
  const target = form.get('target') === '_blank' ? '_blank' : '_self'
  const parent = String(form.get('parent') ?? '').trim() || null
  const visible = form.get('visible') !== 'false'

  if (!label) {
    return c.html(renderMenuFormPage({
      item: null,
      topLevelItems: [],
      user: c.get('user'),
      currentPath: '/admin/menu',
      version: c.get('appVersion'),
      dynamicMenuItems: c.get('pluginMenuItems'),
      error: 'Label is required',
    }), 400)
  }

  const now = Math.floor(Date.now() / 1000)
  const id = nanoid()
  const slug = `menu:user:${id}`
  const isExternal = /^https?:\/\//.test(url)
  const data = JSON.stringify({
    label: escapeHtml(label),
    url,
    icon,
    target,
    isExternal,
    visible,
    parent,
    source: 'user',
    pluginId: null,
    permissions: [],
    lockedFields: [],
  })

  const items = await listMenuItems(db)
  const maxSort = items.reduce((m, i) => Math.max(m, i.sortOrder), 0)
  const sortOrder = maxSort + 10

  await db.prepare(
    `INSERT INTO documents (id, root_id, type_id, type_version, version_of_id, version_number,
       is_current_draft, is_published, status, parent_root_id, slug, path, title, zone,
       sort_order, visible, published_at, scheduled_at, expires_at, deleted_at,
       tenant_id, locale, translation_group_id, data, metadata,
       owner_id, created_by, updated_by, created_at, updated_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(
    id, id, 'menu_item', 1, null, 1,
    1, 1, 'published', '', slug, null, label, null,
    sortOrder, visible ? 1 : 0, now, null, null, null,
    'default', 'default', '', data, '{}',
    null, c.get('user')?.userId ?? 'system', c.get('user')?.userId ?? 'system', now, now
  ).run()

  return c.redirect('/admin/menu?message=Item+created')
})

adminMenuRoutes.put('/reorder', async (c) => {
  const db = c.env.DB
  const body = await c.req.json<Array<{id: string, sortOrder: number, parent: string | null}>>()
  if (!Array.isArray(body)) return c.json({ error: 'Invalid body' }, 400)
  await reorderItems(db, body)
  return c.json({ ok: true })
})

adminMenuRoutes.post('/:id/visibility', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')
  const form = await c.req.formData()
  const visible = form.get('visible') === 'true'
  await toggleVisibility(db, id, visible)
  return c.redirect('/admin/menu?message=Visibility+updated')
})

adminMenuRoutes.put('/:id', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')
  const form = await c.req.formData()

  const items = await listMenuItems(db)
  const item = items.find(i => i.id === id)
  if (!item) return c.json({ error: 'Not found' }, 404)

  const changes: Record<string, any> = {}
  if (form.has('label')) changes.label = escapeHtml(String(form.get('label')).trim())
  if (form.has('icon')) changes.icon = String(form.get('icon')).trim()
  if (form.has('target')) changes.target = form.get('target') === '_blank' ? '_blank' : '_self'
  if (form.has('url')) changes.url = String(form.get('url')).trim()
  if (form.has('parent')) changes.parent = String(form.get('parent')).trim() || null
  if (form.has('visible')) changes.visible = form.get('visible') !== 'false'

  const ok = await updateItem(db, id, changes, item.lockedFields)
  if (!ok) return c.json({ error: 'Cannot modify locked fields' }, 403)

  return c.redirect('/admin/menu?message=Item+updated')
})

adminMenuRoutes.delete('/:id', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')
  const result = await deleteItem(db, id)
  if (!result.ok) return c.json({ error: result.reason }, 403)
  return c.redirect('/admin/menu?message=Item+deleted')
})

adminMenuRoutes.post('/:id/move-up', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')
  const items = await listMenuItems(db)
  const idx = items.findIndex((i) => i.id === id)
  const prev = items[idx - 1]
  const cur = items[idx]
  if (idx > 0 && cur && prev) {
    await reorderItems(db, [
      { id: cur.id, sortOrder: prev.sortOrder, parent: cur.parent },
      { id: prev.id, sortOrder: cur.sortOrder, parent: prev.parent },
    ])
  }
  return c.redirect('/admin/menu?message=Reordered')
})

adminMenuRoutes.post('/:id/move-down', async (c) => {
  const db = c.env.DB
  const id = c.req.param('id')
  const items = await listMenuItems(db)
  const idx = items.findIndex((i) => i.id === id)
  const next = items[idx + 1]
  const cur = items[idx]
  if (idx !== -1 && idx < items.length - 1 && cur && next) {
    await reorderItems(db, [
      { id: cur.id, sortOrder: next.sortOrder, parent: cur.parent },
      { id: next.id, sortOrder: cur.sortOrder, parent: next.parent },
    ])
  }
  return c.redirect('/admin/menu?message=Reordered')
})
