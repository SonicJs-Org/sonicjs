/**
 * Global Variables Plugin
 *
 * Provides dynamic content variables (inline tokens) for rich text fields.
 * Variables are stored as key-value pairs and can be referenced in content
 * using {variable_key} syntax. They are resolved server-side on content read.
 *
 * Part 1: Global Variables Collection (CRUD API + admin UI)
 * Part 3: Server-Side Resolution (token replacement in content)
 * Part 2: Rich Text Inline Tokens (Quill UI) - planned for future PR
 */

import { Hono } from 'hono'
import { z } from 'zod'
import type { Plugin } from '@sonicjs-cms/core'
import { PluginBuilder } from '../../sdk/plugin-builder'
import { resolveVariablesInObject } from './variable-resolver'

// ============================================================================
// Schema & Migration
// ============================================================================

export const globalVariableSchema = z.object({
  id: z.number().optional(),
  key: z.string()
    .min(1, 'Variable key is required')
    .max(100, 'Key must be under 100 characters')
    .regex(/^[a-z0-9_]+$/, 'Key must contain only lowercase letters, numbers, and underscores'),
  value: z.string().max(10000, 'Value must be under 10,000 characters'),
  description: z.string().max(500, 'Description must be under 500 characters').optional(),
  category: z.string().max(50, 'Category must be under 50 characters').optional(),
  isActive: z.boolean().default(true),
  createdAt: z.number().optional(),
  updatedAt: z.number().optional(),
})

export type GlobalVariable = z.infer<typeof globalVariableSchema>

const globalVariablesMigration = `
CREATE TABLE IF NOT EXISTS global_variables (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL UNIQUE,
  value TEXT NOT NULL DEFAULT '',
  description TEXT,
  category TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_global_variables_key ON global_variables(key);
CREATE INDEX IF NOT EXISTS idx_global_variables_category ON global_variables(category);
CREATE INDEX IF NOT EXISTS idx_global_variables_active ON global_variables(is_active);

CREATE TRIGGER IF NOT EXISTS global_variables_updated_at
  AFTER UPDATE ON global_variables
BEGIN
  UPDATE global_variables SET updated_at = strftime('%s', 'now') WHERE id = NEW.id;
END;
`

// ============================================================================
// In-memory variable cache
// ============================================================================

let variableCache: Map<string, string> | null = null
let cacheTimestamp = 0
const CACHE_TTL_MS = 300_000 // 5 minutes

async function getVariablesMap(db: any): Promise<Map<string, string>> {
  const now = Date.now()
  if (variableCache && (now - cacheTimestamp) < CACHE_TTL_MS) {
    return variableCache
  }

  try {
    const { results } = await db.prepare(
      'SELECT key, value FROM global_variables WHERE is_active = 1'
    ).all()

    const map = new Map<string, string>()
    for (const row of results || []) {
      map.set((row as any).key, (row as any).value)
    }

    variableCache = map
    cacheTimestamp = now
    return map
  } catch {
    // Table may not exist yet; return empty map
    return new Map()
  }
}

function invalidateCache(): void {
  variableCache = null
  cacheTimestamp = 0
}

// ============================================================================
// API Routes
// ============================================================================

const apiRoutes = new Hono()

// GET /api/global-variables — List all variables
apiRoutes.get('/', async (c: any) => {
  try {
    const db = c.env?.DB
    if (!db) {
      return c.json({ error: 'Database not available' }, 500)
    }

    const { category, active } = c.req.query()
    let query = 'SELECT * FROM global_variables WHERE 1=1'
    const params: any[] = []

    if (category) {
      query += ' AND category = ?'
      params.push(category)
    }

    if (active !== undefined) {
      query += ' AND is_active = ?'
      params.push(active === 'true' ? 1 : 0)
    }

    query += ' ORDER BY category ASC, key ASC'

    const { results } = await db.prepare(query).bind(...params).all()

    return c.json({
      success: true,
      data: (results || []).map(formatVariable),
    })
  } catch (error) {
    return c.json({ success: false, error: 'Failed to fetch global variables' }, 500)
  }
})

// GET /api/global-variables/resolve — Get a flat key→value map (for frontends)
apiRoutes.get('/resolve', async (c: any) => {
  try {
    const db = c.env?.DB
    if (!db) {
      return c.json({ error: 'Database not available' }, 500)
    }

    const map = await getVariablesMap(db)
    return c.json({
      success: true,
      data: Object.fromEntries(map),
    })
  } catch (error) {
    return c.json({ success: false, error: 'Failed to resolve variables' }, 500)
  }
})

// GET /api/global-variables/:id — Get single variable
apiRoutes.get('/:id', async (c: any) => {
  try {
    const db = c.env?.DB
    if (!db) {
      return c.json({ error: 'Database not available' }, 500)
    }

    const id = c.req.param('id')
    const result = await db.prepare('SELECT * FROM global_variables WHERE id = ?').bind(id).first()

    if (!result) {
      return c.json({ error: 'Variable not found' }, 404)
    }

    return c.json({ success: true, data: formatVariable(result) })
  } catch (error) {
    return c.json({ success: false, error: 'Failed to fetch variable' }, 500)
  }
})

// POST /api/global-variables — Create variable
apiRoutes.post('/', async (c: any) => {
  try {
    const db = c.env?.DB
    if (!db) {
      return c.json({ error: 'Database not available' }, 500)
    }

    const body = await c.req.json()
    const parsed = globalVariableSchema.safeParse(body)
    if (!parsed.success) {
      return c.json({ error: 'Validation failed', details: parsed.error.flatten() }, 400)
    }

    const { key, value, description, category, isActive } = parsed.data

    // Check for duplicate key
    const existing = await db.prepare('SELECT id FROM global_variables WHERE key = ?').bind(key).first()
    if (existing) {
      return c.json({ error: `Variable with key "${key}" already exists` }, 409)
    }

    await db.prepare(
      'INSERT INTO global_variables (key, value, description, category, is_active) VALUES (?, ?, ?, ?, ?)'
    ).bind(key, value, description || null, category || null, isActive ? 1 : 0).run()

    invalidateCache()

    const created = await db.prepare('SELECT * FROM global_variables WHERE key = ?').bind(key).first()
    return c.json({ success: true, data: formatVariable(created) }, 201)
  } catch (error) {
    return c.json({ success: false, error: 'Failed to create variable' }, 500)
  }
})

// PUT /api/global-variables/:id — Update variable
apiRoutes.put('/:id', async (c: any) => {
  try {
    const db = c.env?.DB
    if (!db) {
      return c.json({ error: 'Database not available' }, 500)
    }

    const id = c.req.param('id')
    const existing = await db.prepare('SELECT * FROM global_variables WHERE id = ?').bind(id).first()
    if (!existing) {
      return c.json({ error: 'Variable not found' }, 404)
    }

    const body = await c.req.json()
    const updates: string[] = []
    const params: any[] = []

    if (body.key !== undefined) {
      const keyValidation = z.string().min(1).max(100).regex(/^[a-z0-9_]+$/).safeParse(body.key)
      if (!keyValidation.success) {
        return c.json({ error: 'Invalid key format' }, 400)
      }
      // Check uniqueness if key changed
      if (body.key !== (existing as any).key) {
        const dup = await db.prepare('SELECT id FROM global_variables WHERE key = ? AND id != ?').bind(body.key, id).first()
        if (dup) {
          return c.json({ error: `Variable with key "${body.key}" already exists` }, 409)
        }
      }
      updates.push('key = ?')
      params.push(body.key)
    }

    if (body.value !== undefined) {
      updates.push('value = ?')
      params.push(body.value)
    }

    if (body.description !== undefined) {
      updates.push('description = ?')
      params.push(body.description)
    }

    if (body.category !== undefined) {
      updates.push('category = ?')
      params.push(body.category)
    }

    if (body.isActive !== undefined) {
      updates.push('is_active = ?')
      params.push(body.isActive ? 1 : 0)
    }

    if (updates.length === 0) {
      return c.json({ error: 'No fields to update' }, 400)
    }

    params.push(id)
    await db.prepare(`UPDATE global_variables SET ${updates.join(', ')} WHERE id = ?`).bind(...params).run()

    invalidateCache()

    const updated = await db.prepare('SELECT * FROM global_variables WHERE id = ?').bind(id).first()
    return c.json({ success: true, data: formatVariable(updated) })
  } catch (error) {
    return c.json({ success: false, error: 'Failed to update variable' }, 500)
  }
})

// DELETE /api/global-variables/:id — Delete variable
apiRoutes.delete('/:id', async (c: any) => {
  try {
    const db = c.env?.DB
    if (!db) {
      return c.json({ error: 'Database not available' }, 500)
    }

    const id = c.req.param('id')
    const existing = await db.prepare('SELECT id FROM global_variables WHERE id = ?').bind(id).first()
    if (!existing) {
      return c.json({ error: 'Variable not found' }, 404)
    }

    await db.prepare('DELETE FROM global_variables WHERE id = ?').bind(id).run()
    invalidateCache()

    return c.json({ success: true })
  } catch (error) {
    return c.json({ success: false, error: 'Failed to delete variable' }, 500)
  }
})

// ============================================================================
// Admin Routes
// ============================================================================

const adminRoutes = new Hono()

adminRoutes.get('/', async (c: any) => {
  const db = c.env?.DB
  let variables: any[] = []

  try {
    if (db) {
      const { results } = await db.prepare(
        'SELECT * FROM global_variables ORDER BY category ASC, key ASC'
      ).all()
      variables = (results || []).map(formatVariable)
    }
  } catch {
    // Table may not exist yet
  }

  const categories = [...new Set(variables.map((v: any) => v.category).filter(Boolean))]

  return c.html(renderAdminPage(variables, categories))
})

// ============================================================================
// Helpers
// ============================================================================

function formatVariable(row: any): any {
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

function renderAdminPage(variables: any[], categories: string[]): string {
  const rows = variables.map((v: any) => `
    <tr class="border-b border-zinc-200 dark:border-zinc-700">
      <td class="px-4 py-3 font-mono text-sm text-blue-600 dark:text-blue-400">{${v.key}}</td>
      <td class="px-4 py-3 text-sm max-w-xs truncate">${escapeHtml(v.value)}</td>
      <td class="px-4 py-3 text-sm text-zinc-500">${escapeHtml(v.description || '')}</td>
      <td class="px-4 py-3 text-sm">${v.category ? `<span class="px-2 py-0.5 bg-zinc-100 dark:bg-zinc-800 rounded text-xs">${escapeHtml(v.category)}</span>` : ''}</td>
      <td class="px-4 py-3 text-center">
        <span class="inline-block w-2 h-2 rounded-full ${v.isActive ? 'bg-green-500' : 'bg-zinc-400'}"></span>
      </td>
    </tr>
  `).join('')

  return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Global Variables - SonicJS</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>tailwind.config = { darkMode: 'class' }</script>
</head>
<body class="bg-white dark:bg-zinc-950 text-zinc-950 dark:text-white min-h-screen">
  <div class="p-8">
    <div class="mb-8">
      <h1 class="text-3xl font-bold mb-2">Global Variables</h1>
      <p class="text-zinc-600 dark:text-zinc-400">
        Manage dynamic content variables. Use <code class="text-sm bg-zinc-100 dark:bg-zinc-800 px-1.5 py-0.5 rounded">{variable_key}</code> syntax in rich text fields.
      </p>
    </div>

    <div class="bg-white dark:bg-zinc-900 rounded-lg border border-zinc-200 dark:border-zinc-800 shadow-sm overflow-hidden">
      <table class="w-full">
        <thead>
          <tr class="border-b border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800/50">
            <th class="px-4 py-3 text-left text-xs font-medium text-zinc-500 uppercase">Token</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-zinc-500 uppercase">Value</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-zinc-500 uppercase">Description</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-zinc-500 uppercase">Category</th>
            <th class="px-4 py-3 text-center text-xs font-medium text-zinc-500 uppercase">Active</th>
          </tr>
        </thead>
        <tbody>
          ${rows || '<tr><td colspan="5" class="px-4 py-8 text-center text-zinc-500">No variables defined yet. Use the API to create variables.</td></tr>'}
        </tbody>
      </table>
    </div>

    <div class="mt-6 bg-blue-50 dark:bg-blue-950 border border-blue-200 dark:border-blue-800 rounded-lg p-6">
      <h3 class="font-semibold text-blue-900 dark:text-blue-100 mb-2">API Reference</h3>
      <ul class="text-sm text-blue-800 dark:text-blue-200 space-y-1">
        <li><code>GET /api/global-variables</code> &mdash; List all variables</li>
        <li><code>GET /api/global-variables/resolve</code> &mdash; Get key&rarr;value map</li>
        <li><code>POST /api/global-variables</code> &mdash; Create variable</li>
        <li><code>PUT /api/global-variables/:id</code> &mdash; Update variable</li>
        <li><code>DELETE /api/global-variables/:id</code> &mdash; Delete variable</li>
      </ul>
    </div>
  </div>
</body>
</html>`
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

// ============================================================================
// Plugin Builder
// ============================================================================

export function createGlobalVariablesPlugin(): Plugin {
  const builder = PluginBuilder.create({
    name: 'global-variables',
    version: '1.0.0-beta.1',
    description: 'Dynamic content variables with inline token support for rich text fields',
  })

  builder.metadata({
    author: { name: 'SonicJS Team', email: 'team@sonicjs.com' },
    license: 'MIT',
    compatibility: '^2.0.0',
  })

  // Database model
  builder.addModel('GlobalVariable', {
    tableName: 'global_variables',
    schema: globalVariableSchema,
    migrations: [globalVariablesMigration],
  })

  // API routes
  builder.addRoute('/api/global-variables', apiRoutes, {
    description: 'Global variables CRUD API',
    requiresAuth: true,
    priority: 50,
  })

  // Admin page
  builder.addRoute('/admin/global-variables', adminRoutes, {
    description: 'Global variables admin page',
    requiresAuth: true,
    priority: 50,
  })

  // Menu item
  builder.addMenuItem('Global Variables', '/admin/global-variables', {
    icon: 'variable',
    order: 45,
    permissions: ['global-variables:view'],
  })

  // Hook: resolve variables in content on read
  builder.addHook('content:read', async (data: any, context: any) => {
    try {
      const db = context?.context?.env?.DB
      if (!db || !data) return data

      const variables = await getVariablesMap(db)
      if (variables.size === 0) return data

      return resolveVariablesInObject(data, variables)
    } catch {
      // Don't break content reads if resolution fails
      return data
    }
  }, {
    priority: 50,
    description: 'Resolve {variable_key} tokens in content data',
  })

  // Lifecycle
  builder.lifecycle({
    activate: async (ctx: any) => {
      // Run migration to create table
      try {
        const db = ctx?.env?.DB
        if (db) {
          // Split migration into individual statements
          const statements = globalVariablesMigration
            .split(';')
            .map((s: string) => s.trim())
            .filter((s: string) => s.length > 0)

          for (const statement of statements) {
            await db.prepare(statement).run()
          }
          console.info('[GlobalVariables] Table created/verified')
        }
      } catch (error) {
        console.error('[GlobalVariables] Migration error:', error)
      }
      console.info('[GlobalVariables] Plugin activated')
    },
    deactivate: async () => {
      invalidateCache()
      console.info('[GlobalVariables] Plugin deactivated')
    },
  })

  return builder.build() as Plugin
}

export const globalVariablesPlugin = createGlobalVariablesPlugin()

// Re-export resolver for direct use
export { resolveVariables, resolveVariablesInObject } from './variable-resolver'
export { getVariablesMap, invalidateCache }
