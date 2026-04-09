/**
 * Global Variables Plugin — Enhanced
 *
 * Extends PR #743 (lane711/sonicjs) with:
 * - Full CRUD admin page (add, inline edit, delete, toggle active/inactive)
 * - Proper PluginBuilder lifecycle (install, activate, deactivate, uninstall)
 * - Content read hook for {variable_key} server-side resolution
 *
 * Rich text editor integration: Quill blots (blue chips) + TinyMCE buttons via PluginManager
 *
 * @see https://github.com/lane711/sonicjs/issues/719
 * @see https://github.com/lane711/sonicjs/pull/743
 */

import { Hono } from 'hono'
import { PluginBuilder } from '../../sdk/plugin-builder'
import { wrapAdminPage } from '../_shared/admin-template'
import {
  resolveVariablesInObject,
  invalidateVariablesCache,
  getVariablesCached,
  setVariablesCache,
} from './variable-resolver'
import {
  getSharedQuillStyles,
  getSharedQuillScript,
  getQuillEnhancerPollerScript,
} from '../_shared/quill-shared'
import {
  getSharedTinyMceStyles,
  getTinyMcePluginScript,
} from '../_shared/tinymce-shared'

// ─── Migration SQL ───────────────────────────────────────────────────────────

const MIGRATION_SQL = `
CREATE TABLE IF NOT EXISTS global_variables (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL UNIQUE,
  value TEXT NOT NULL DEFAULT '',
  description TEXT,
  category TEXT DEFAULT 'general',
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_global_variables_key ON global_variables(key);
CREATE INDEX IF NOT EXISTS idx_global_variables_category ON global_variables(category);
CREATE INDEX IF NOT EXISTS idx_global_variables_active ON global_variables(is_active);
`

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatVariable(row: any) {
  if (!row) return null
  return {
    id: row.id,
    key: row.key,
    value: row.value,
    description: row.description,
    category: row.category,
    isActive: row.is_active === 1 || row.is_active === true,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }
}

function esc(s: string): string {
  return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

async function getVariablesMap(db: any): Promise<Map<string, string>> {
  let variables = getVariablesCached()
  if (variables) return variables
  try {
    const { results } = await db.prepare(
      'SELECT key, value FROM global_variables WHERE is_active = 1'
    ).all()
    variables = new Map<string, string>()
    for (const row of results || []) {
      variables.set((row as any).key, (row as any).value)
    }
    setVariablesCache(variables)
    return variables
  } catch {
    return new Map()
  }
}

// ─── API Routes ──────────────────────────────────────────────────────────────

const apiRoutes = new Hono()

// Gate: all routes return 404 if this plugin is inactive
apiRoutes.use('*', async (c: any, next: any) => {
  try {
    const db = c.env?.DB
    if (db) {
      const row = await db.prepare("SELECT status FROM plugins WHERE id = 'global-variables' AND status = 'active'").first()
      if (!row) return c.json({ error: 'Plugin not active' }, 404)
    }
  } catch { /* allow if table doesn't exist yet */ }
  await next()
})

apiRoutes.get('/', async (c: any) => {
  try {
    const db = c.env.DB
    const category = c.req.query('category')
    const active = c.req.query('active')

    let query = 'SELECT * FROM global_variables WHERE 1=1'
    const params: any[] = []
    if (category) { query += ' AND category = ?'; params.push(category) }
    if (active !== undefined) { query += ' AND is_active = ?'; params.push(active === 'true' ? 1 : 0) }
    query += ' ORDER BY category ASC, key ASC'

    const { results } = await db.prepare(query).bind(...params).all()
    return c.json({ success: true, data: (results || []).map(formatVariable) })
  } catch {
    return c.json({ success: false, error: 'Failed to fetch global variables' }, 500)
  }
})

apiRoutes.get('/resolve', async (c: any) => {
  try {
    const map = await getVariablesMap(c.env.DB)
    return c.json({ success: true, data: Object.fromEntries(map) })
  } catch {
    return c.json({ success: false, error: 'Failed to resolve variables' }, 500)
  }
})

apiRoutes.get('/:id', async (c: any) => {
  try {
    const result = await c.env.DB.prepare('SELECT * FROM global_variables WHERE id = ?').bind(c.req.param('id')).first()
    if (!result) return c.json({ error: 'Variable not found' }, 404)
    return c.json({ success: true, data: formatVariable(result) })
  } catch {
    return c.json({ success: false, error: 'Failed to fetch variable' }, 500)
  }
})

apiRoutes.post('/', async (c: any) => {
  try {
    const db = c.env.DB
    const { key, value, description, category, isActive } = await c.req.json()
    if (!key || !/^[a-z0-9_]+$/.test(key)) {
      return c.json({ error: 'Key must be lowercase alphanumeric with underscores' }, 400)
    }
    const existing = await db.prepare('SELECT id FROM global_variables WHERE key = ?').bind(key).first()
    if (existing) return c.json({ error: `Variable with key "${key}" already exists` }, 409)

    await db.prepare(
      'INSERT INTO global_variables (key, value, description, category, is_active) VALUES (?, ?, ?, ?, ?)'
    ).bind(key, value || '', description || '', category || 'general', isActive !== false ? 1 : 0).run()
    invalidateVariablesCache()

    const created = await db.prepare('SELECT * FROM global_variables WHERE key = ?').bind(key).first()
    return c.json({ success: true, data: formatVariable(created) }, 201)
  } catch {
    return c.json({ success: false, error: 'Failed to create variable' }, 500)
  }
})

apiRoutes.put('/:id', async (c: any) => {
  try {
    const db = c.env.DB
    const id = c.req.param('id')
    const existing = await db.prepare('SELECT * FROM global_variables WHERE id = ?').bind(id).first() as any
    if (!existing) return c.json({ error: 'Variable not found' }, 404)

    const body = await c.req.json()
    const updates: string[] = []
    const params: any[] = []

    if (body.value !== undefined) { updates.push('value = ?'); params.push(body.value) }
    if (body.description !== undefined) { updates.push('description = ?'); params.push(body.description) }
    if (body.category !== undefined) { updates.push('category = ?'); params.push(body.category) }
    if (body.isActive !== undefined) { updates.push('is_active = ?'); params.push(body.isActive ? 1 : 0) }
    if (body.key !== undefined) {
      if (!/^[a-z0-9_]+$/.test(body.key)) return c.json({ error: 'Invalid key format' }, 400)
      if (body.key !== existing.key) {
        const dup = await db.prepare('SELECT id FROM global_variables WHERE key = ? AND id != ?').bind(body.key, id).first()
        if (dup) return c.json({ error: `Key "${body.key}" already exists` }, 409)
      }
      updates.push('key = ?'); params.push(body.key)
    }

    if (updates.length === 0) return c.json({ error: 'No fields to update' }, 400)
    updates.push('updated_at = strftime(\'%s\', \'now\')')
    params.push(id)
    await db.prepare(`UPDATE global_variables SET ${updates.join(', ')} WHERE id = ?`).bind(...params).run()
    invalidateVariablesCache()

    const updated = await db.prepare('SELECT * FROM global_variables WHERE id = ?').bind(id).first()
    return c.json({ success: true, data: formatVariable(updated) })
  } catch {
    return c.json({ success: false, error: 'Failed to update variable' }, 500)
  }
})

apiRoutes.delete('/:id', async (c: any) => {
  try {
    const db = c.env.DB
    const id = c.req.param('id')
    const existing = await db.prepare('SELECT id FROM global_variables WHERE id = ?').bind(id).first()
    if (!existing) return c.json({ error: 'Variable not found' }, 404)
    await db.prepare('DELETE FROM global_variables WHERE id = ?').bind(id).run()
    invalidateVariablesCache()
    return c.json({ success: true })
  } catch {
    return c.json({ success: false, error: 'Failed to delete variable' }, 500)
  }
})

// ─── Admin Page ──────────────────────────────────────────────────────────────

const adminRoutes = new Hono()

adminRoutes.use('*', async (c: any, next: any) => {
  try {
    const db = c.env?.DB
    if (db) {
      const row = await db.prepare("SELECT status FROM plugins WHERE id = 'global-variables' AND status = 'active'").first()
      if (!row) return c.html('<html><body><h1>Plugin not active</h1><p>Enable the Global Variables plugin from <a href="/admin/plugins">Plugins</a>.</p></body></html>', 404)
    }
  } catch { /* allow */ }
  await next()
})

adminRoutes.get('/', async (c: any) => {
  const db = c.env.DB
  let variables: any[] = []
  try {
    const { results } = await db.prepare('SELECT * FROM global_variables ORDER BY category ASC, key ASC').all()
    variables = (results || []).map(formatVariable)
  } catch { /* table may not exist yet */ }

  // Fetch editor integration status
  let editorActive = false
  let activeEditorName = ''
  let enableEditorIntegration = true
  try {
    const qeRow = await db.prepare("SELECT status FROM plugins WHERE (id = 'quill-editor' OR name = 'quill-editor') AND status = 'active'").first()
    const tmRow = await db.prepare("SELECT status FROM plugins WHERE (id = 'tinymce-plugin' OR name = 'tinymce-plugin') AND status = 'active'").first()
    if (qeRow) { editorActive = true; activeEditorName = 'Quill Editor' }
    else if (tmRow) { editorActive = true; activeEditorName = 'TinyMCE' }
    const gvRow = await db.prepare("SELECT settings FROM plugins WHERE id = 'global-variables'").first() as any
    if (gvRow?.settings) {
      const settings = typeof gvRow.settings === 'string' ? JSON.parse(gvRow.settings) : gvRow.settings
      enableEditorIntegration = settings.enableEditorIntegration !== false
    }
  } catch { /* ignore */ }

  return c.html(renderAdminPage(variables, { editorActive, activeEditorName, enableEditorIntegration }))
})

// HTMX: inline update value
adminRoutes.put('/:id', async (c: any) => {
  const db = c.env.DB
  const id = c.req.param('id')
  let body: any
  try { body = await c.req.json() } catch { body = await c.req.parseBody() }
  const value = body.value
  if (value !== undefined) {
    await db.prepare('UPDATE global_variables SET value = ?, updated_at = strftime(\'%s\', \'now\') WHERE id = ?').bind(value, id).run()
    invalidateVariablesCache()
  }
  return c.html('<span class="text-green-400 text-xs">Saved</span>')
})

// HTMX: toggle active
adminRoutes.post('/:id/toggle', async (c: any) => {
  const db = c.env.DB
  const id = c.req.param('id')
  await db.prepare('UPDATE global_variables SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END, updated_at = strftime(\'%s\', \'now\') WHERE id = ?').bind(id).run()
  invalidateVariablesCache()
  c.header('HX-Redirect', '/admin/global-variables')
  return c.body(null, 204)
})

// HTMX: create variable
adminRoutes.post('/', async (c: any) => {
  const db = c.env.DB
  const form = await c.req.parseBody()
  const key = (form.key as string || '').trim()
  const value = (form.value as string || '').trim()
  const category = (form.category as string || 'general').trim()
  const description = (form.description as string || '').trim()

  if (!key || !/^[a-z0-9_]+$/.test(key)) {
    return c.html('<div class="bg-red-500/10 border border-red-500/30 text-red-400 text-sm rounded-lg px-4 py-2 mb-4">Key must be lowercase alphanumeric with underscores only</div>')
  }

  const existing = await db.prepare('SELECT id FROM global_variables WHERE key = ?').bind(key).first()
  if (existing) {
    return c.html(`<div class="bg-red-500/10 border border-red-500/30 text-red-400 text-sm rounded-lg px-4 py-2 mb-4">Variable with key "${esc(key)}" already exists</div>`)
  }

  await db.prepare(
    'INSERT INTO global_variables (key, value, description, category) VALUES (?, ?, ?, ?)'
  ).bind(key, value, description, category).run()
  invalidateVariablesCache()

  c.header('HX-Redirect', '/admin/global-variables')
  return c.body(null, 204)
})

// Toggle editor integration setting
adminRoutes.post('/settings/editor-integration', async (c: any) => {
  const db = c.env.DB
  try {
    const row = await db.prepare("SELECT settings FROM plugins WHERE id = 'global-variables'").first() as any
    const settings = row?.settings ? (typeof row.settings === 'string' ? JSON.parse(row.settings) : row.settings) : {}
    settings.enableEditorIntegration = !settings.enableEditorIntegration
    await db.prepare("UPDATE plugins SET settings = ? WHERE id = 'global-variables'").bind(JSON.stringify(settings)).run()
    return c.json({ success: true, enableEditorIntegration: settings.enableEditorIntegration })
  } catch {
    return c.json({ success: false, error: 'Failed to update setting' }, 500)
  }
})

// HTMX: delete variable
adminRoutes.delete('/:id', async (c: any) => {
  const db = c.env.DB
  await db.prepare('DELETE FROM global_variables WHERE id = ?').bind(c.req.param('id')).run()
  invalidateVariablesCache()
  return c.html('')
})

// ─── Admin Page Template ─────────────────────────────────────────────────────

function renderAdminPage(variables: any[], editorStatus: { editorActive: boolean; activeEditorName: string; enableEditorIntegration: boolean } = { editorActive: false, activeEditorName: '', enableEditorIntegration: true }): string {
  // Group by category
  const groups = new Map<string, any[]>()
  for (const v of variables) {
    const cat = v.category || 'general'
    if (!groups.has(cat)) groups.set(cat, [])
    groups.get(cat)!.push(v)
  }

  const categoryHtml = Array.from(groups.entries()).map(([cat, vars]) => `
    <div class="mb-6">
      <h3 class="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-2 flex items-center gap-2">
        <span class="w-1.5 h-1.5 rounded-full bg-blue-500"></span>
        ${esc(cat)} <span class="text-zinc-600">(${vars.length})</span>
      </h3>
      <div class="bg-white dark:bg-zinc-900 rounded-lg border border-zinc-200 dark:border-zinc-800 overflow-hidden">
        <table class="w-full">
          <tbody>
            ${vars.map(v => `
              <tr class="border-b border-zinc-100 dark:border-zinc-800 last:border-0 group" id="var-${v.id}" data-original="${esc(v.value)}">
                <td class="px-4 py-3 w-48">
                  <code class="text-sm font-mono text-blue-600 dark:text-blue-400">{${esc(v.key)}}</code>
                  ${v.description ? `<div class="text-xs text-zinc-500 mt-0.5 truncate max-w-[200px]">${esc(v.description)}</div>` : ''}
                </td>
                <td class="px-4 py-3">
                  <div class="flex items-center gap-2">
                    <input type="text" value="${esc(v.value)}" data-id="${v.id}"
                           class="var-value-input flex-1 rounded-md border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800 px-3 py-1.5 text-sm text-zinc-900 dark:text-zinc-100 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:bg-white dark:focus:bg-zinc-900"
                           oninput="markDirty(this)" />
                    <button onclick="saveVariable(${v.id}, this)" class="save-btn hidden rounded-md bg-blue-600 px-3 py-1 text-xs font-medium text-white hover:bg-blue-500 transition-colors">
                      Save
                    </button>
                    <span class="save-status text-xs w-16"></span>
                  </div>
                </td>
                <td class="px-3 py-3 w-20 text-center">
                  <button onclick="toggleVariable(${v.id})"
                          class="inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium transition-colors cursor-pointer
                          ${v.isActive ? 'bg-green-500/10 text-green-600 dark:text-green-400 hover:bg-green-500/20' : 'bg-zinc-100 dark:bg-zinc-800 text-zinc-500 hover:bg-zinc-200 dark:hover:bg-zinc-700'}"
                          title="Click to ${v.isActive ? 'deactivate' : 'activate'}">
                    ${v.isActive ? 'Active' : 'Off'}
                  </button>
                </td>
                <td class="px-3 py-3 w-10">
                  <button onclick="deleteVariable(${v.id}, '{${esc(v.key)}}')"
                          class="rounded p-1.5 text-zinc-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-500/10 opacity-0 group-hover:opacity-100 transition-all"
                          title="Delete">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                  </button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `).join('')

  return wrapAdminPage({ title: 'Global Variables', body: `
  <div class="max-w-4xl mx-auto px-6 py-8">
    <!-- Header -->
    <div class="flex items-center justify-between mb-6">
      <div>
        <div class="flex items-center gap-2 mb-1">
          <a href="/admin/dashboard" class="text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300 transition-colors">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/></svg>
          </a>
          <h1 class="text-2xl font-bold">Global Variables</h1>
        </div>
        <p class="text-sm text-zinc-500">
          Dynamic content tokens. Use <code class="text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-500/10 px-1.5 py-0.5 rounded text-xs">{variable_key}</code> in rich text — resolved server-side on content read.
        </p>
      </div>
      <div class="text-sm text-zinc-500">${variables.length} variable${variables.length !== 1 ? 's' : ''}</div>
    </div>

    <!-- Variables list -->
    <div id="variables-list">
      ${categoryHtml || `
        <div class="bg-white dark:bg-zinc-900 rounded-lg border border-zinc-200 dark:border-zinc-800 p-12 text-center">
          <div class="text-4xl mb-3">🔤</div>
          <h3 class="text-lg font-medium mb-1">No variables yet</h3>
          <p class="text-sm text-zinc-500">Create your first variable below to get started.</p>
        </div>
      `}
    </div>

    <!-- Add new variable form -->
    <div class="mt-6 bg-white dark:bg-zinc-900 rounded-lg border border-zinc-200 dark:border-zinc-800 p-5">
      <h3 class="text-sm font-semibold mb-3">Add Variable</h3>
      <form class="space-y-3">
        <div class="grid grid-cols-12 gap-3">
          <div class="col-span-3">
            <label class="block text-xs text-zinc-500 mb-1">Key</label>
            <input type="text" name="key" required pattern="[a-z0-9_]+" placeholder="variable_key"
                   class="w-full rounded-md border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800 px-3 py-2 text-sm font-mono placeholder-zinc-400 focus:border-blue-500 focus:ring-1 focus:ring-blue-500" />
          </div>
          <div class="col-span-3">
            <label class="block text-xs text-zinc-500 mb-1">Value</label>
            <input type="text" name="value" required placeholder="Value"
                   class="w-full rounded-md border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800 px-3 py-2 text-sm placeholder-zinc-400 focus:border-blue-500 focus:ring-1 focus:ring-blue-500" />
          </div>
          <div class="col-span-2">
            <label class="block text-xs text-zinc-500 mb-1">Category</label>
            <input type="text" name="category" placeholder="general" value="general"
                   class="w-full rounded-md border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800 px-3 py-2 text-sm placeholder-zinc-400 focus:border-blue-500 focus:ring-1 focus:ring-blue-500" />
          </div>
          <div class="col-span-3">
            <label class="block text-xs text-zinc-500 mb-1">Description</label>
            <input type="text" name="description" placeholder="Optional"
                   class="w-full rounded-md border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800 px-3 py-2 text-sm placeholder-zinc-400 focus:border-blue-500 focus:ring-1 focus:ring-blue-500" />
          </div>
          <div class="col-span-1 flex items-end">
            <button type="submit" class="w-full rounded-md bg-zinc-900 dark:bg-white px-3 py-2 text-sm font-medium text-white dark:text-zinc-900 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors">
              Add
            </button>
          </div>
        </div>
      </form>
    </div>

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
            Adds a <strong>Var</strong> toolbar button to the rich text editor for inserting global variables as inline chips. Works with both Quill and TinyMCE.
          </p>
        </div>
        ${editorStatus.editorActive
          ? `<button onclick="toggleEditorIntegration()" id="editor-toggle-btn"
                    class="relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 ${editorStatus.enableEditorIntegration ? 'bg-blue-600' : 'bg-zinc-600'}"
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
                  To use variable insertion in the editor, enable either the <strong>Quill Editor</strong> or <strong>TinyMCE</strong> plugin from the
                  <a href="/admin/plugins" class="underline hover:text-yellow-500">Plugins page</a>.
                </p>
              </div>
            </div>
          </div>`
        : ''
      }
    </div>

    <!-- API reference -->
    <details class="mt-6">
      <summary class="text-sm text-zinc-500 cursor-pointer hover:text-zinc-700 dark:hover:text-zinc-300">API Reference</summary>
      <div class="mt-2 bg-zinc-100 dark:bg-zinc-900 rounded-lg border border-zinc-200 dark:border-zinc-800 p-4 text-sm text-zinc-600 dark:text-zinc-400 space-y-1">
        <div><code>GET /api/global-variables</code> — List all</div>
        <div><code>GET /api/global-variables/resolve</code> — Key→value map</div>
        <div><code>POST /api/global-variables</code> — Create <code>{ key, value, description, category }</code></div>
        <div><code>PUT /api/global-variables/:id</code> — Update <code>{ value, description, category, isActive }</code></div>
        <div><code>DELETE /api/global-variables/:id</code> — Delete</div>
      </div>
    </details>

    <!-- Toast container -->
    <div id="toast" class="fixed bottom-6 right-6 z-50 hidden">
      <div class="rounded-lg px-4 py-3 text-sm font-medium shadow-lg transition-all" id="toast-inner"></div>
    </div>

    <!-- JavaScript: save/delete/toggle via fetch (handles CSRF properly) -->
    <script>
      function showToast(message, type) {
        var toast = document.getElementById('toast');
        var inner = document.getElementById('toast-inner');
        inner.textContent = message;
        inner.className = 'rounded-lg px-4 py-3 text-sm font-medium shadow-lg transition-all ' +
          (type === 'success' ? 'bg-green-600 text-white' :
           type === 'error' ? 'bg-red-600 text-white' : 'bg-zinc-700 text-white');
        toast.classList.remove('hidden');
        setTimeout(function() { toast.classList.add('hidden'); }, 3000);
      }

      function markDirty(input) {
        var row = input.closest('tr');
        var original = row.getAttribute('data-original');
        var saveBtn = row.querySelector('.save-btn');
        var status = row.querySelector('.save-status');
        if (input.value !== original) {
          saveBtn.classList.remove('hidden');
          status.textContent = '';
          input.classList.add('border-yellow-500');
        } else {
          saveBtn.classList.add('hidden');
          input.classList.remove('border-yellow-500');
        }
      }

      async function saveVariable(id, btn) {
        var row = document.getElementById('var-' + id);
        var input = row.querySelector('.var-value-input');
        var status = row.querySelector('.save-status');
        btn.disabled = true;
        btn.textContent = 'Saving...';
        try {
          var resp = await fetch('/api/global-variables/' + id, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ value: input.value })
          });
          var json = await resp.json();
          if (json.success) {
            row.setAttribute('data-original', input.value);
            input.classList.remove('border-yellow-500');
            btn.classList.add('hidden');
            status.innerHTML = '<span class="text-green-500">Saved</span>';
            showToast('Variable updated', 'success');
            setTimeout(function() { status.textContent = ''; }, 2000);
          } else {
            showToast(json.error || 'Save failed', 'error');
          }
        } catch(e) {
          showToast('Network error', 'error');
        }
        btn.disabled = false;
        btn.textContent = 'Save';
      }

      async function toggleVariable(id) {
        try {
          // Get current state, flip it
          var resp = await fetch('/api/global-variables/' + id);
          var json = await resp.json();
          if (!json.success) { showToast('Failed to load variable', 'error'); return; }
          var newState = !json.data.isActive;
          var resp2 = await fetch('/api/global-variables/' + id, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ isActive: newState })
          });
          var json2 = await resp2.json();
          if (json2.success) {
            showToast(newState ? 'Activated' : 'Deactivated', 'success');
            setTimeout(function() { location.reload(); }, 500);
          } else {
            showToast(json2.error || 'Toggle failed', 'error');
          }
        } catch(e) {
          showToast('Network error', 'error');
        }
      }

      async function deleteVariable(id, keyName) {
        if (!confirm('Delete variable ' + keyName + '?')) return;
        try {
          var resp = await fetch('/api/global-variables/' + id, { method: 'DELETE' });
          var json = await resp.json();
          if (json.success) {
            document.getElementById('var-' + id).remove();
            showToast('Variable deleted', 'success');
          } else {
            showToast(json.error || 'Delete failed', 'error');
          }
        } catch(e) {
          showToast('Network error', 'error');
        }
      }

      async function toggleEditorIntegration() {
        try {
          var resp = await fetch('/admin/global-variables/settings/editor-integration', { method: 'POST' });
          var json = await resp.json();
          if (json.success) {
            showToast(json.enableEditorIntegration ? 'Quill integration enabled' : 'Quill integration disabled', 'success');
            setTimeout(function() { location.reload(); }, 500);
          } else {
            showToast(json.error || 'Failed to update', 'error');
          }
        } catch(e) {
          showToast('Network error', 'error');
        }
      }

      // Add form submit via fetch (not HTMX)
      document.querySelector('form').addEventListener('submit', async function(e) {
        e.preventDefault();
        var form = e.target;
        var data = {
          key: form.key.value.trim(),
          value: form.value.value.trim(),
          category: form.category.value.trim() || 'general',
          description: form.description.value.trim()
        };
        if (!data.key || !/^[a-z0-9_]+$/.test(data.key)) {
          showToast('Key must be lowercase alphanumeric with underscores', 'error');
          return;
        }
        try {
          var resp = await fetch('/api/global-variables', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
          });
          var json = await resp.json();
          if (json.success) {
            showToast('Variable created', 'success');
            setTimeout(function() { location.reload(); }, 500);
          } else {
            showToast(json.error || 'Create failed', 'error');
          }
        } catch(e) {
          showToast('Network error', 'error');
        }
      });
    </script>
  </div>
  ` })
}

// ─── Plugin Builder ──────────────────────────────────────────────────────────

export function createGlobalVariablesPlugin() {
  const builder = PluginBuilder.create({
    name: 'global-variables',
    version: '1.1.0',
    description: 'Dynamic content variables with inline token support and CRUD admin page',
  })

  builder.metadata({
    author: { name: 'SonicJS Community', email: 'community@sonicjs.com' },
    license: 'MIT',
    compatibility: '^2.0.0',
  })

  builder.addRoute('/api/global-variables', apiRoutes, {
    description: 'Global variables CRUD API',
    requiresAuth: true,
    priority: 50,
  })

  builder.addRoute('/admin/global-variables', adminRoutes, {
    description: 'Global variables admin page with full CRUD',
    requiresAuth: true,
    priority: 50,
  })

  builder.addMenuItem('Global Variables', '/admin/global-variables', {
    icon: 'variable',
    order: 45,
    permissions: ['global-variables:view'],
  })

  builder.addHook('content:read', async (data: any, context: any) => {
    try {
      const db = context?.context?.env?.DB
      if (!db || !data) return data
      const variables = await getVariablesMap(db)
      if (variables.size === 0) return data
      return resolveVariablesInObject(data, variables)
    } catch {
      return data
    }
  }, {
    priority: 50,
    description: 'Resolve {variable_key} tokens in content data',
  })

  builder.lifecycle({
    install: async (ctx: any) => {
      const db = ctx?.env?.DB
      if (db) {
        const statements = MIGRATION_SQL.split(';').map(s => s.trim()).filter(s => s.length > 0)
        for (const stmt of statements) { await db.prepare(stmt).run() }
        console.info('[GlobalVariables] Tables created')
      }
    },
    activate: async () => {
      console.info('[GlobalVariables] Plugin activated')
    },
    deactivate: async () => {
      invalidateVariablesCache()
      console.info('[GlobalVariables] Plugin deactivated, cache cleared')
    },
    uninstall: async (ctx: any) => {
      const db = ctx?.env?.DB
      if (db) {
        await db.prepare('DROP TABLE IF EXISTS global_variables').run()
        console.info('[GlobalVariables] Tables dropped')
      }
    },
  })

  return builder.build()
}

export const globalVariablesPlugin = createGlobalVariablesPlugin()

// Export raw route handlers for direct mounting
export { apiRoutes as globalVariablesApiRoutes, adminRoutes as globalVariablesAdminRoutes }

// Re-export resolver
export { resolveVariables, resolveVariablesInObject } from './variable-resolver'

// ─── Quill Blot Integration ─────────────────────────────────────────────────
// Self-contained Variable blot for the Quill editor.
// Returns injectable HTML (styles + scripts) that registers a VariableBlot
// and adds a "Var" toolbar button with a searchable picker dropdown.
//
// Depends on shared infrastructure from quill-shared.ts (picker, proxy, poller).
// The shared code is idempotent — safe to include from both plugins.

export function getVariableBlotScript(): string {
  return getSharedQuillStyles() + getSharedQuillScript() + `
    <script>
    (function() {
      function waitForQuill(cb) {
        if (typeof Quill !== 'undefined') return cb();
        setTimeout(function() { waitForQuill(cb); }, 50);
      }

      waitForQuill(function() {
        // ─── Register Variable Blot ────────────────────────────────
        var Embed = Quill.import('blots/embed');

        function VariableBlot() {
          return Reflect.construct(Embed, arguments, VariableBlot);
        }
        Object.setPrototypeOf(VariableBlot.prototype, Embed.prototype);
        Object.setPrototypeOf(VariableBlot, Embed);

        VariableBlot.blotName = 'variable';
        VariableBlot.tagName = 'SPAN';
        VariableBlot.className = 'ql-variable-blot';

        VariableBlot.create = function(value) {
          var node = Embed.create.call(this);
          var key = (value && value.key) ? value.key : (typeof value === 'string' ? value : '');
          node.setAttribute('data-variable-key', key);
          node.setAttribute('contenteditable', 'false');
          node.innerText = key;
          return node;
        };

        VariableBlot.value = function(node) {
          return { key: node.getAttribute('data-variable-key') || '' };
        };

        Quill.register(VariableBlot, true);

        // ─── Register toolbar enhancer ─────────────────────────────
        window.__sonicQuillEnhancers = window.__sonicQuillEnhancers || [];
        window.__sonicQuillEnhancers.push(function(container, quill, toolbar) {
          // Skip if already added
          if (toolbar.querySelector('.ql-insertVariable')) return;

          var shared = window.__sonicQuillShared;
          var varBtn = document.createElement('button');
          varBtn.className = 'ql-insertVariable';
          varBtn.type = 'button';
          varBtn.innerHTML = '\\u{1f524} Var';
          varBtn.title = 'Insert Global Variable';
          varBtn.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            var savedRange = quill.getSelection() || { index: quill.getLength() - 1 };
            shared.showPicker({
              button: varBtn,
              icon: '\\u{1f524}',
              label: 'variables',
              apiUrl: '/api/global-variables?active=true',
              filterActive: false,
              renderItem: function(item) {
                return '<span class="item-key" style="color:#60a5fa">{' + item.key + '}</span>'
                     + '<span class="item-value">' + ((item.value || '') + '').substring(0, 40) + '</span>';
              },
              getSearchText: function(item) {
                return item.key + ' ' + (item.value || '') + ' ' + (item.description || '') + ' ' + (item.category || '');
              },
              onSelect: function(item) {
                shared.insertBlot(quill, savedRange.index, 'variable', { key: item.key });
              }
            });
          });

          var sep = document.createElement('span');
          sep.className = 'ql-formats';
          sep.appendChild(varBtn);
          toolbar.appendChild(sep);
        });
      });
    })();
    </script>
  ` + getQuillEnhancerPollerScript();
}

// ─── TinyMCE Integration ────────────────────────────────────────────────────
// Self-contained Variable integration for the TinyMCE editor.
// Adds a "Var" toolbar button, renders variables as noneditable chips,
// serializes back to {key} syntax on save.

export function getVariableTinyMceScript(): string {
  return getSharedTinyMceStyles() + getTinyMcePluginScript({
    buttonName: 'sonicInsertVar',
    buttonText: '\\u{1f524} Var',
    buttonTooltip: 'Insert Global Variable',
    pickerIcon: '\\u{1f524}',
    pickerLabel: 'variables',
    pickerApiUrl: '/api/global-variables?active=true',
    renderItemJs: `function(item) {
      return '<span class="item-key" style="color:#60a5fa">{' + item.key + '}</span>'
           + '<span class="item-value">' + ((item.value || '') + '').substring(0, 40) + '</span>';
    }`,
    getSearchTextJs: `function(item) {
      return item.key + ' ' + (item.value || '') + ' ' + (item.description || '') + ' ' + (item.category || '');
    }`,
    onSelectJs: `function(editor, item) {
      editor.insertContent('<span class="sonic-var-chip" contenteditable="false" data-var-key="' + item.key + '">' + item.key + '</span>&nbsp;');
    }`,
  });
}
