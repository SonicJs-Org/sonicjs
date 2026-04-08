/**
 * Shortcodes Plugin
 *
 * Registered shortcode functions for dynamic content in rich text fields.
 * Use [[shortcode_name param="value"]] syntax — resolved server-side on content read.
 *
 * Features:
 * - Handler registry for custom shortcode functions
 * - CRUD API for managing shortcode definitions
 * - Admin page with handler status badges and live preview
 * - content:read hook for automatic resolution
 * - Built-in handlers: current_date, phone_link, cta_button, plan_count, provider_rating
 *
 * @see https://github.com/lane711/sonicjs/issues/719 (shortcodes mentioned as future extension)
 */

import { Hono } from 'hono'
import { PluginBuilder } from '../../../sdk/plugin-builder'
import { wrapAdminPage } from '../_shared/admin-template'
import {
  resolveShortcodesInObject,
  resolveShortcodes,
  getRegisteredHandlers,
  hasHandler,
} from './shortcode-resolver'
import {
  getSharedQuillStyles,
  getSharedQuillScript,
  getQuillEnhancerPollerScript,
} from '../_shared/quill-shared'
import {
  getSharedTinyMceStyles,
  getTinyMcePluginScript,
} from '../_shared/tinymce-shared'

// Re-export for consumers
export { registerShortcodeHandler, getRegisteredHandlers } from './shortcode-resolver'

// ─── Migration SQL ───────────────────────────────────────────────────────────

const MIGRATION_SQL = `
CREATE TABLE IF NOT EXISTS shortcodes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL DEFAULT '',
  description TEXT,
  category TEXT DEFAULT 'general',
  handler_key TEXT NOT NULL,
  default_params TEXT DEFAULT '{}',
  example_usage TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_shortcodes_name ON shortcodes(name);
CREATE INDEX IF NOT EXISTS idx_shortcodes_category ON shortcodes(category);
CREATE INDEX IF NOT EXISTS idx_shortcodes_active ON shortcodes(is_active);
`

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatShortcode(row: any) {
  if (!row) return null
  let defaultParams = {}
  try { defaultParams = typeof row.default_params === 'string' ? JSON.parse(row.default_params) : (row.default_params || {}) } catch { /* */ }
  return {
    id: row.id,
    name: row.name,
    displayName: row.display_name,
    description: row.description,
    category: row.category,
    handlerKey: row.handler_key,
    defaultParams: defaultParams,
    exampleUsage: row.example_usage,
    isActive: row.is_active === 1 || row.is_active === true,
    handlerRegistered: hasHandler(row.handler_key),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }
}

function esc(s: string): string {
  return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

// ─── API Routes ──────────────────────────────────────────────────────────────

const apiRoutes = new Hono()

apiRoutes.use('*', async (c: any, next: any) => {
  try {
    const db = c.env?.DB
    if (db) {
      const row = await db.prepare("SELECT status FROM plugins WHERE id = 'shortcodes' AND status = 'active'").first()
      if (!row) return c.json({ error: 'Plugin not active' }, 404)
    }
  } catch { /* allow */ }
  await next()
})

apiRoutes.get('/', async (c: any) => {
  try {
    const db = c.env.DB
    const active = c.req.query('active')
    const resolvable = c.req.query('resolvable')
    let query = 'SELECT * FROM shortcodes'
    const params: any[] = []
    if (active !== undefined) { query += ' WHERE is_active = ?'; params.push(active === 'true' ? 1 : 0) }
    query += ' ORDER BY category ASC, name ASC'

    const { results } = await db.prepare(query).bind(...params).all()
    let data = (results || []).map(formatShortcode)

    // Filter to only shortcodes with registered handlers (resolvable on content read)
    if (resolvable === 'true') {
      data = data.filter((sc: any) => sc.handlerRegistered)
    }

    return c.json({ success: true, data })
  } catch {
    return c.json({ success: false, error: 'Failed to fetch shortcodes' }, 500)
  }
})

apiRoutes.get('/handlers/registered', async (c: any) => {
  return c.json({ success: true, data: getRegisteredHandlers() })
})

apiRoutes.post('/preview', async (c: any) => {
  try {
    const { text } = await c.req.json()
    if (!text) return c.json({ error: 'text is required' }, 400)
    const output = await resolveShortcodes(text)
    return c.json({ success: true, data: { input: text, output } })
  } catch {
    return c.json({ success: false, error: 'Failed to preview shortcode' }, 500)
  }
})

apiRoutes.get('/:id', async (c: any) => {
  try {
    const result = await c.env.DB.prepare('SELECT * FROM shortcodes WHERE id = ?').bind(c.req.param('id')).first()
    if (!result) return c.json({ error: 'Shortcode not found' }, 404)
    return c.json({ success: true, data: formatShortcode(result) })
  } catch {
    return c.json({ success: false, error: 'Failed to fetch shortcode' }, 500)
  }
})

apiRoutes.post('/', async (c: any) => {
  try {
    const db = c.env.DB
    const { name, display_name, displayName, description, handler_key, handlerKey, default_params, defaultParams, example_usage, exampleUsage, category } = await c.req.json()
    const scName = name
    const scHandlerKey = handler_key || handlerKey
    const scDisplayName = display_name || displayName || scName
    const scDefaultParams = default_params || defaultParams || {}
    const scExampleUsage = example_usage || exampleUsage || ''

    if (!scName || !/^\w+$/.test(scName)) return c.json({ error: 'Name must be alphanumeric with underscores' }, 400)
    if (!scHandlerKey) return c.json({ error: 'handler_key is required' }, 400)

    const existing = await db.prepare('SELECT id FROM shortcodes WHERE name = ?').bind(scName).first()
    if (existing) return c.json({ error: `Shortcode "${scName}" already exists` }, 409)

    await db.prepare(
      'INSERT INTO shortcodes (name, display_name, description, handler_key, default_params, example_usage, category) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(scName, scDisplayName, description || '', scHandlerKey, JSON.stringify(scDefaultParams), scExampleUsage, category || 'general').run()

    const created = await db.prepare('SELECT * FROM shortcodes WHERE name = ?').bind(scName).first()
    return c.json({ success: true, data: formatShortcode(created) }, 201)
  } catch {
    return c.json({ success: false, error: 'Failed to create shortcode' }, 500)
  }
})

apiRoutes.put('/:id', async (c: any) => {
  try {
    const db = c.env.DB
    const id = c.req.param('id')
    const existing = await db.prepare('SELECT * FROM shortcodes WHERE id = ?').bind(id).first()
    if (!existing) return c.json({ error: 'Shortcode not found' }, 404)

    const body = await c.req.json()
    const updates: string[] = []
    const params: any[] = []

    if (body.display_name !== undefined || body.displayName !== undefined) { updates.push('display_name = ?'); params.push(body.display_name || body.displayName) }
    if (body.description !== undefined) { updates.push('description = ?'); params.push(body.description) }
    if (body.handler_key !== undefined || body.handlerKey !== undefined) { updates.push('handler_key = ?'); params.push(body.handler_key || body.handlerKey) }
    if (body.default_params !== undefined || body.defaultParams !== undefined) { updates.push('default_params = ?'); params.push(JSON.stringify(body.default_params || body.defaultParams)) }
    if (body.example_usage !== undefined || body.exampleUsage !== undefined) { updates.push('example_usage = ?'); params.push(body.example_usage || body.exampleUsage) }
    if (body.category !== undefined) { updates.push('category = ?'); params.push(body.category) }
    if (body.isActive !== undefined || body.is_active !== undefined) { updates.push('is_active = ?'); params.push((body.isActive ?? body.is_active) ? 1 : 0) }

    if (updates.length === 0) return c.json({ error: 'No fields to update' }, 400)
    updates.push('updated_at = strftime(\'%s\', \'now\')')
    params.push(id)
    await db.prepare(`UPDATE shortcodes SET ${updates.join(', ')} WHERE id = ?`).bind(...params).run()

    const updated = await db.prepare('SELECT * FROM shortcodes WHERE id = ?').bind(id).first()
    return c.json({ success: true, data: formatShortcode(updated) })
  } catch {
    return c.json({ success: false, error: 'Failed to update shortcode' }, 500)
  }
})

apiRoutes.delete('/:id', async (c: any) => {
  try {
    const db = c.env.DB
    const id = c.req.param('id')
    const existing = await db.prepare('SELECT id FROM shortcodes WHERE id = ?').bind(id).first()
    if (!existing) return c.json({ error: 'Shortcode not found' }, 404)
    await db.prepare('DELETE FROM shortcodes WHERE id = ?').bind(id).run()
    return c.json({ success: true })
  } catch {
    return c.json({ success: false, error: 'Failed to delete shortcode' }, 500)
  }
})

// ─── Admin Page ──────────────────────────────────────────────────────────────

const adminRoutes = new Hono()

adminRoutes.use('*', async (c: any, next: any) => {
  try {
    const db = c.env?.DB
    if (db) {
      const row = await db.prepare("SELECT status FROM plugins WHERE id = 'shortcodes' AND status = 'active'").first()
      if (!row) return c.html('<html><body><h1>Plugin not active</h1><p>Enable the Shortcodes plugin from <a href="/admin/plugins">Plugins</a>.</p></body></html>', 404)
    }
  } catch { /* allow */ }
  await next()
})

adminRoutes.get('/', async (c: any) => {
  const db = c.env.DB
  let shortcodes: any[] = []
  try {
    const { results } = await db.prepare('SELECT * FROM shortcodes ORDER BY category ASC, name ASC').all()
    shortcodes = (results || []).map(formatShortcode)
  } catch { /* table may not exist */ }

  // Fetch editor integration status
  let editorActive = false
  let activeEditorName = ''
  let enableEditorIntegration = true
  try {
    const qeRow = await db.prepare("SELECT status FROM plugins WHERE (id = 'quill-editor' OR name = 'quill-editor') AND status = 'active'").first()
    const tmRow = await db.prepare("SELECT status FROM plugins WHERE (id = 'tinymce-plugin' OR name = 'tinymce-plugin') AND status = 'active'").first()
    if (qeRow) { editorActive = true; activeEditorName = 'Quill Editor' }
    else if (tmRow) { editorActive = true; activeEditorName = 'TinyMCE' }
    const scRow = await db.prepare("SELECT settings FROM plugins WHERE id = 'shortcodes'").first() as any
    if (scRow?.settings) {
      const settings = typeof scRow.settings === 'string' ? JSON.parse(scRow.settings) : scRow.settings
      enableEditorIntegration = settings.enableEditorIntegration !== false
    }
  } catch { /* ignore */ }

  return c.html(renderAdminPage(shortcodes, { editorActive, activeEditorName, enableEditorIntegration }))
})

// HTMX: create
adminRoutes.post('/', async (c: any) => {
  const db = c.env.DB
  const form = await c.req.parseBody()
  const name = (form.name as string || '').trim()
  const displayName = (form.display_name as string || name).trim()
  const handlerKey = (form.handler_key as string || '').trim()
  const category = (form.category as string || 'general').trim()
  const description = (form.description as string || '').trim()
  const exampleUsage = (form.example_usage as string || '').trim()

  if (!name || !/^\w+$/.test(name)) {
    return c.html('<div class="bg-red-500/10 border border-red-500/30 text-red-400 text-sm rounded-lg px-4 py-2 mb-4">Name must be alphanumeric with underscores</div>')
  }
  if (!handlerKey) {
    return c.html('<div class="bg-red-500/10 border border-red-500/30 text-red-400 text-sm rounded-lg px-4 py-2 mb-4">Handler is required</div>')
  }

  await db.prepare(
    'INSERT OR IGNORE INTO shortcodes (name, display_name, description, handler_key, default_params, example_usage, category) VALUES (?, ?, ?, ?, \'{}\', ?, ?)'
  ).bind(name, displayName, description, handlerKey, exampleUsage, category).run()

  c.header('HX-Redirect', '/admin/shortcodes')
  return c.body(null, 204)
})

// Toggle editor integration setting
adminRoutes.post('/settings/editor-integration', async (c: any) => {
  const db = c.env.DB
  try {
    const row = await db.prepare("SELECT settings FROM plugins WHERE id = 'shortcodes'").first() as any
    const settings = row?.settings ? (typeof row.settings === 'string' ? JSON.parse(row.settings) : row.settings) : {}
    settings.enableEditorIntegration = !settings.enableEditorIntegration
    await db.prepare("UPDATE plugins SET settings = ? WHERE id = 'shortcodes'").bind(JSON.stringify(settings)).run()
    return c.json({ success: true, enableEditorIntegration: settings.enableEditorIntegration })
  } catch {
    return c.json({ success: false, error: 'Failed to update setting' }, 500)
  }
})

// HTMX: delete
adminRoutes.delete('/:id', async (c: any) => {
  await c.env.DB.prepare('DELETE FROM shortcodes WHERE id = ?').bind(c.req.param('id')).run()
  return c.html('')
})

// ─── Admin Page Template ─────────────────────────────────────────────────────

function renderAdminPage(shortcodes: any[], editorStatus: { editorActive: boolean; activeEditorName: string; enableEditorIntegration: boolean } = { editorActive: false, activeEditorName: '', enableEditorIntegration: true }): string {
  const groups = new Map<string, any[]>()
  for (const sc of shortcodes) {
    const cat = sc.category || 'general'
    if (!groups.has(cat)) groups.set(cat, [])
    groups.get(cat)!.push(sc)
  }

  const handlers = getRegisteredHandlers()

  const categoryHtml = Array.from(groups.entries()).map(([cat, scs]) => `
    <div class="mb-6">
      <h3 class="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2 flex items-center gap-2">
        <span class="w-1.5 h-1.5 rounded-full bg-purple-500"></span>
        ${esc(cat)} <span class="text-zinc-600">(${scs.length})</span>
      </h3>
      <div class="space-y-2">
        ${scs.map(sc => `
          <div class="bg-white dark:bg-zinc-900 rounded-lg border border-zinc-200 dark:border-zinc-800 p-4 group" id="sc-${sc.id}">
            <div class="flex items-start justify-between gap-4">
              <div class="flex-1 min-w-0">
                <div class="flex items-center gap-2 mb-1">
                  <span class="text-sm font-semibold">${esc(sc.displayName || sc.name)}</span>
                  <code class="text-xs font-mono text-purple-600 dark:text-purple-400 bg-purple-50 dark:bg-purple-500/10 rounded px-1.5 py-0.5">[[${esc(sc.name)}]]</code>
                  <span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs ${sc.isActive ? 'bg-green-500/10 text-green-600 dark:text-green-400' : 'bg-zinc-100 dark:bg-zinc-800 text-zinc-500'}">
                    ${sc.isActive ? 'Active' : 'Off'}
                  </span>
                  ${sc.handlerRegistered
                    ? '<span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs bg-blue-500/10 text-blue-600 dark:text-blue-400" title="Resolves to inline HTML on content read">Resolvable</span>'
                    : '<span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs bg-red-500/10 text-red-600 dark:text-red-400" title="No handler registered — will not resolve in content">No handler</span>'
                  }
                </div>
                ${sc.description ? `<p class="text-xs text-zinc-500 mb-1">${esc(sc.description)}</p>` : ''}
                ${sc.exampleUsage ? `<code class="text-xs font-mono text-zinc-500 bg-zinc-50 dark:bg-zinc-800 rounded px-2 py-0.5">${esc(sc.exampleUsage)}</code>` : ''}
              </div>
              <button hx-delete="/admin/shortcodes/${sc.id}" hx-confirm="Delete shortcode '${esc(sc.name)}'?"
                      hx-target="#sc-${sc.id}" hx-swap="outerHTML"
                      class="rounded p-1.5 text-zinc-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-500/10 opacity-0 group-hover:opacity-100 transition-all">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
              </button>
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `).join('')

  const handlerOptions = handlers.map(h => `<option value="${h}">${h}</option>`).join('')

  return wrapAdminPage({ title: 'Shortcodes', body: `
  <div class="max-w-4xl mx-auto px-6 py-8">
    <div class="flex items-center justify-between mb-6">
      <div>
        <div class="flex items-center gap-2 mb-1">
          <a href="/admin/dashboard" class="text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300 transition-colors">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/></svg>
          </a>
          <h1 class="text-2xl font-bold">Shortcodes</h1>
        </div>
        <p class="text-sm text-zinc-500">
          Inline content functions. Use <code class="text-purple-600 dark:text-purple-400 bg-purple-50 dark:bg-purple-500/10 px-1.5 py-0.5 rounded text-xs">[[shortcode_name param="value"]]</code> in rich text — each resolves to an inline HTML string on content read. Only shortcodes with registered handlers are available in the Quill editor picker.
        </p>
      </div>
      <div class="text-sm text-zinc-500">${shortcodes.length} shortcode${shortcodes.length !== 1 ? 's' : ''} &middot; ${handlers.length} handler${handlers.length !== 1 ? 's' : ''}</div>
    </div>

    <div id="shortcodes-list">
      ${categoryHtml || `
        <div class="bg-white dark:bg-zinc-900 rounded-lg border border-zinc-200 dark:border-zinc-800 p-12 text-center">
          <div class="text-4xl mb-3">⚡</div>
          <h3 class="text-lg font-medium mb-1">No shortcodes yet</h3>
          <p class="text-sm text-zinc-500">Register a shortcode below.</p>
        </div>
      `}
    </div>

    <!-- Add shortcode form -->
    <div class="mt-6 bg-white dark:bg-zinc-900 rounded-lg border border-zinc-200 dark:border-zinc-800 p-5">
      <h3 class="text-sm font-semibold mb-3">Register Shortcode</h3>
      <form hx-post="/admin/shortcodes" hx-target="#form-errors" hx-swap="innerHTML" class="space-y-3">
        <div id="form-errors"></div>
        <div class="grid grid-cols-12 gap-3">
          <div class="col-span-3">
            <label class="block text-xs text-zinc-500 mb-1">Name</label>
            <input type="text" name="name" required pattern="\\w+" placeholder="my_shortcode"
                   class="w-full rounded-md border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800 px-3 py-2 text-sm font-mono placeholder-zinc-400 focus:border-purple-500 focus:ring-1 focus:ring-purple-500" />
          </div>
          <div class="col-span-3">
            <label class="block text-xs text-zinc-500 mb-1">Display Name</label>
            <input type="text" name="display_name" required placeholder="My Shortcode"
                   class="w-full rounded-md border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800 px-3 py-2 text-sm placeholder-zinc-400 focus:border-purple-500 focus:ring-1 focus:ring-purple-500" />
          </div>
          <div class="col-span-3">
            <label class="block text-xs text-zinc-500 mb-1">Handler</label>
            <select name="handler_key" required
                    class="w-full rounded-md border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800 px-3 py-2 text-sm focus:border-purple-500 focus:ring-1 focus:ring-purple-500">
              <option value="">Select...</option>
              ${handlerOptions}
            </select>
          </div>
          <div class="col-span-2">
            <label class="block text-xs text-zinc-500 mb-1">Category</label>
            <input type="text" name="category" value="general"
                   class="w-full rounded-md border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800 px-3 py-2 text-sm placeholder-zinc-400 focus:border-purple-500 focus:ring-1 focus:ring-purple-500" />
          </div>
          <div class="col-span-1 flex items-end">
            <button type="submit" class="w-full rounded-md bg-zinc-900 dark:bg-white px-3 py-2 text-sm font-medium text-white dark:text-zinc-900 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors">
              Add
            </button>
          </div>
        </div>
      </form>
    </div>

    <!-- Preview -->
    <div class="mt-6 bg-white dark:bg-zinc-900 rounded-lg border border-zinc-200 dark:border-zinc-800 p-5">
      <h3 class="text-sm font-semibold mb-3">Preview</h3>
      <div class="flex gap-3">
        <input type="text" id="preview-input" placeholder='[[current_date format="MM/DD/YYYY"]]'
               class="flex-1 rounded-md border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800 px-3 py-2 text-sm font-mono placeholder-zinc-400 focus:border-purple-500 focus:ring-1 focus:ring-purple-500" />
        <button onclick="previewShortcode()" class="rounded-md bg-zinc-200 dark:bg-zinc-800 px-4 py-2 text-sm hover:bg-zinc-300 dark:hover:bg-zinc-700 transition-colors">Preview</button>
      </div>
      <div id="preview-output" class="mt-3 bg-zinc-50 dark:bg-zinc-800 rounded-md p-3 text-sm hidden"></div>
    </div>

    <script>
      async function previewShortcode() {
        var input = document.getElementById('preview-input').value;
        if (!input) return;
        var resp = await fetch('/api/shortcodes/preview', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: input })
        });
        var json = await resp.json();
        var output = document.getElementById('preview-output');
        output.classList.remove('hidden');
        output.innerHTML = '<span class="text-zinc-500 text-xs">Output:</span><br>' + (json.data?.output || json.error || 'No output');
      }
    </script>

    <!-- Rich Text Editor Integration -->
    <div class="mt-6 bg-white dark:bg-zinc-900 rounded-lg border border-zinc-200 dark:border-zinc-800 p-5">
      <div class="flex items-center justify-between">
        <div>
          <h3 class="text-sm font-semibold flex items-center gap-2">
            Rich Text Editor Integration
            ${editorStatus.editorActive && editorStatus.enableEditorIntegration
              ? `<span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs bg-green-500/10 text-green-600 dark:text-green-400">Active — ${esc(editorStatus.activeEditorName)}</span>`
              : '<span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs bg-zinc-100 dark:bg-zinc-800 text-zinc-500">Inactive</span>'
            }
          </h3>
          <p class="text-xs text-zinc-500 mt-1">
            Adds an <strong>SC</strong> toolbar button to the rich text editor for inserting shortcodes as inline chips. Works with both Quill and TinyMCE.
          </p>
        </div>
        ${editorStatus.editorActive
          ? `<button onclick="toggleEditorIntegration()" id="editor-toggle-btn"
                    class="relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-2 ${editorStatus.enableEditorIntegration ? 'bg-purple-600' : 'bg-zinc-600'}"
                    role="switch" aria-checked="${editorStatus.enableEditorIntegration}">
              <span class="pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${editorStatus.enableEditorIntegration ? 'translate-x-5' : 'translate-x-0'}"></span>
            </button>`
          : ''
        }
      </div>
      ${!editorStatus.editorActive
        ? `<div class="mt-3 rounded-md bg-yellow-500/10 border border-yellow-500/20 px-4 py-3">
            <div class="flex items-start gap-2">
              <svg class="w-5 h-5 text-yellow-500 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"/></svg>
              <div>
                <p class="text-sm font-medium text-yellow-600 dark:text-yellow-400">No rich text editor plugin is active</p>
                <p class="text-xs text-yellow-600/80 dark:text-yellow-400/80 mt-0.5">
                  To use shortcode insertion in the editor, enable either the <strong>Quill Editor</strong> or <strong>TinyMCE</strong> plugin from the
                  <a href="/admin/plugins" class="underline hover:text-yellow-500">Plugins page</a>.
                </p>
              </div>
            </div>
          </div>`
        : ''
      }
    </div>

    <script>
      async function toggleEditorIntegration() {
        try {
          var resp = await fetch('/admin/shortcodes/settings/editor-integration', { method: 'POST' });
          var json = await resp.json();
          if (json.success) {
            var toast = document.createElement('div');
            toast.className = 'fixed bottom-6 right-6 z-50 rounded-lg px-4 py-3 text-sm font-medium shadow-lg bg-green-600 text-white';
            toast.textContent = json.enableEditorIntegration ? 'Editor integration enabled' : 'Editor integration disabled';
            document.body.appendChild(toast);
            setTimeout(function() { location.reload(); }, 500);
          }
        } catch(e) {
          alert('Network error');
        }
      }
    </script>

    <details class="mt-6">
      <summary class="text-sm text-zinc-500 cursor-pointer hover:text-zinc-700 dark:hover:text-zinc-300">API Reference</summary>
      <div class="mt-2 bg-zinc-100 dark:bg-zinc-900 rounded-lg border border-zinc-200 dark:border-zinc-800 p-4 text-sm text-zinc-600 dark:text-zinc-400 space-y-1">
        <div><code>GET /api/shortcodes</code> — List all</div>
        <div><code>GET /api/shortcodes/handlers/registered</code> — Handler keys</div>
        <div><code>POST /api/shortcodes/preview</code> — Live preview</div>
        <div><code>POST /api/shortcodes</code> — Create</div>
        <div><code>PUT /api/shortcodes/:id</code> — Update</div>
        <div><code>DELETE /api/shortcodes/:id</code> — Delete</div>
      </div>
    </details>
  </div>
  ` })
}

// ─── Plugin Builder ──────────────────────────────────────────────────────────

export function createShortcodesPlugin() {
  const builder = PluginBuilder.create({
    name: 'shortcodes',
    version: '1.0.0',
    description: 'Registered shortcode functions for dynamic content with [[shortcode]] syntax',
  })

  builder.metadata({
    author: { name: 'SonicJS Community', email: 'community@sonicjs.com' },
    license: 'MIT',
    compatibility: '^2.0.0',
  })

  builder.addRoute('/api/shortcodes', apiRoutes, {
    description: 'Shortcodes CRUD API + preview + handler list',
    requiresAuth: true,
    priority: 50,
  })

  builder.addRoute('/admin/shortcodes', adminRoutes, {
    description: 'Shortcodes admin page with CRUD and preview',
    requiresAuth: true,
    priority: 50,
  })

  builder.addMenuItem('Shortcodes', '/admin/shortcodes', {
    icon: 'bolt',
    order: 46,
    permissions: ['shortcodes:view'],
  })

  builder.addHook('content:read', async (data: any, context: any) => {
    try {
      if (!data) return data
      return resolveShortcodesInObject(data, context)
    } catch {
      return data
    }
  }, {
    priority: 60, // Run after global-variables (50)
    description: 'Resolve [[shortcode]] tokens in content data',
  })

  builder.lifecycle({
    install: async (ctx: any) => {
      const db = ctx?.env?.DB
      if (db) {
        const statements = MIGRATION_SQL.split(';').map(s => s.trim()).filter(s => s.length > 0)
        for (const stmt of statements) { await db.prepare(stmt).run() }
        console.info('[Shortcodes] Tables created')
      }
    },
    activate: async () => {
      console.info('[Shortcodes] Plugin activated')
    },
    deactivate: async () => {
      console.info('[Shortcodes] Plugin deactivated')
    },
    uninstall: async (ctx: any) => {
      const db = ctx?.env?.DB
      if (db) {
        await db.prepare('DROP TABLE IF EXISTS shortcodes').run()
        console.info('[Shortcodes] Tables dropped')
      }
    },
  })

  return builder.build()
}

export const shortcodesPlugin = createShortcodesPlugin()

// Export raw route handlers for direct mounting
export { apiRoutes as shortcodesApiRoutes, adminRoutes as shortcodesAdminRoutes }

// Re-export resolver
export { resolveShortcodes, resolveShortcodesInObject } from './shortcode-resolver'

// ─── Quill Blot Integration ─────────────────────────────────────────────────
// Self-contained Shortcode blot for the Quill editor.
// Returns injectable HTML (styles + scripts) that registers a ShortcodeBlot
// and adds a "SC" toolbar button with a searchable picker dropdown.
//
// Depends on shared infrastructure from quill-shared.ts (picker, proxy, poller).
// The shared code is idempotent — safe to include from both plugins.

export function getShortcodeBlotScript(): string {
  return getSharedQuillStyles() + getSharedQuillScript() + `
    <script>
    (function() {
      function waitForQuill(cb) {
        if (typeof Quill !== 'undefined') return cb();
        setTimeout(function() { waitForQuill(cb); }, 50);
      }

      waitForQuill(function() {
        // ─── Register Shortcode Blot ───────────────────────────────
        var Embed = Quill.import('blots/embed');

        function ShortcodeBlot() {
          return Reflect.construct(Embed, arguments, ShortcodeBlot);
        }
        Object.setPrototypeOf(ShortcodeBlot.prototype, Embed.prototype);
        Object.setPrototypeOf(ShortcodeBlot, Embed);

        ShortcodeBlot.blotName = 'shortcode';
        ShortcodeBlot.tagName = 'SPAN';
        ShortcodeBlot.className = 'ql-shortcode-blot';

        ShortcodeBlot.create = function(value) {
          var node = Embed.create.call(this);
          var name = (value && value.name) ? value.name : (typeof value === 'string' ? value : '');
          var params = (value && value.params) ? value.params : '';
          node.setAttribute('data-shortcode-name', name);
          if (params) node.setAttribute('data-shortcode-params', params);
          node.setAttribute('contenteditable', 'false');
          node.innerText = name + (params ? ' ' + params : '');
          return node;
        };

        ShortcodeBlot.value = function(node) {
          return {
            name: node.getAttribute('data-shortcode-name') || '',
            params: node.getAttribute('data-shortcode-params') || ''
          };
        };

        Quill.register(ShortcodeBlot, true);

        // ─── Register toolbar enhancer ─────────────────────────────
        window.__sonicQuillEnhancers = window.__sonicQuillEnhancers || [];
        window.__sonicQuillEnhancers.push(function(container, quill, toolbar) {
          // Skip if already added
          if (toolbar.querySelector('.ql-insertShortcode')) return;

          var shared = window.__sonicQuillShared;
          var scBtn = document.createElement('button');
          scBtn.className = 'ql-insertShortcode';
          scBtn.type = 'button';
          scBtn.innerHTML = '\\u26A1 SC';
          scBtn.title = 'Insert Shortcode';
          scBtn.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            var savedRange = quill.getSelection() || { index: quill.getLength() - 1 };
            shared.showPicker({
              button: scBtn,
              icon: '\\u26A1',
              label: 'shortcodes',
              apiUrl: '/api/shortcodes?active=true&resolvable=true',
              filterActive: false,
              renderItem: function(item) {
                return '<span class="item-key" style="color:#c084fc">[[' + item.name + ']]</span>'
                     + '<span class="item-value">' + (item.display_name || item.name) + '</span>';
              },
              getSearchText: function(item) {
                return item.name + ' ' + (item.display_name || '') + ' ' + (item.description || '') + ' ' + (item.category || '');
              },
              onSelect: function(item) {
                var params = '';
                try {
                  var dp = typeof item.default_params === 'string' ? JSON.parse(item.default_params) : (item.default_params || {});
                  var paramParts = [];
                  Object.keys(dp).forEach(function(k) { paramParts.push(k + '="' + dp[k] + '"'); });
                  if (paramParts.length) params = paramParts.join(' ');
                } catch(ex) {}
                shared.insertBlot(quill, savedRange.index, 'shortcode', { name: item.name, params: params });
              }
            });
          });

          var sep = document.createElement('span');
          sep.className = 'ql-formats';
          sep.appendChild(scBtn);
          toolbar.appendChild(sep);
        });
      });
    })();
    </script>
  ` + getQuillEnhancerPollerScript();
}

// ─── TinyMCE Integration ────────────────────────────────────────────────────
// Self-contained Shortcode integration for the TinyMCE editor.
// Adds a "SC" toolbar button, renders shortcodes as noneditable chips,
// serializes back to [[name params]] syntax on save.

export function getShortcodeTinyMceScript(): string {
  return getSharedTinyMceStyles() + getTinyMcePluginScript({
    buttonName: 'sonicInsertSC',
    buttonText: '\\u26A1 SC',
    buttonTooltip: 'Insert Shortcode',
    pickerIcon: '\\u26A1',
    pickerLabel: 'shortcodes',
    pickerApiUrl: '/api/shortcodes?active=true&resolvable=true',
    renderItemJs: `function(item) {
      return '<span class="item-key" style="color:#c084fc">[[' + item.name + ']]</span>'
           + '<span class="item-value">' + (item.display_name || item.name) + '</span>';
    }`,
    getSearchTextJs: `function(item) {
      return item.name + ' ' + (item.display_name || '') + ' ' + (item.description || '') + ' ' + (item.category || '');
    }`,
    onSelectJs: `function(editor, item) {
      var params = '';
      try {
        var dp = typeof item.default_params === 'string' ? JSON.parse(item.default_params) : (item.default_params || {});
        var pp = [];
        Object.keys(dp).forEach(function(k) { pp.push(k + '="' + dp[k] + '"'); });
        if (pp.length) params = pp.join(' ');
      } catch(ex) {}
      var label = item.name + (params ? ' ' + params : '');
      var pa = params ? ' data-sc-params="' + params.replace(/"/g, '&amp;quot;') + '"' : '';
      editor.insertContent('<span class="sonic-sc-chip" contenteditable="false" data-sc-name="' + item.name + '"' + pa + '>' + label + '</span>&nbsp;');
    }`,
  });
}
