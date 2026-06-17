/**
 * Admin Collections (read-only)
 *
 * Collections are code-defined — registered via `registerCollections()` in the
 * app entry point or a plugin's `onBoot`. This file provides:
 *   GET /admin/collections          — list page (old UI restored)
 *   GET /admin/collections/new      — instructional page (no create form)
 *   GET /admin/collections/:id      — detail / field viewer (read-only)
 *
 * The old POST/PUT/DELETE handlers were removed in the drop-db-collections plan
 * (see docs/ai/plans/drop-db-collections-plan.md). Collections are code-only.
 */

import { Hono } from 'hono'
import { html } from 'hono/html'
import { requireAuth } from '../middleware'
import { isPluginActive } from '../middleware/plugin-middleware'
import { renderCollectionsListPage } from '../templates/pages/admin-collections-list.template'
import { renderCollectionFormPage } from '../templates/pages/admin-collections-form.template'
import { loadCollectionConfigs, isCodeCollectionInternal, isDbDocTypeInternal } from '../services/collection-loader'
import { getCollectionRegistry } from '../services/collection-registry'
import { renderAdminLayoutCatalyst } from '../templates/layouts/admin-layout-catalyst.template'
import { getCoreVersion } from '../utils/version'
import { escapeHtml } from '../utils/sanitize'

// Type definitions for collections
interface Collection {
  id: string
  name: string
  display_name: string
  description?: string
  created_at: number
  formattedDate: string
  field_count?: number
  managed?: boolean
  source_type?: string | null
  internal?: boolean
  versioning?: boolean
}

interface CollectionFormData {
  id?: string
  name?: string
  display_name?: string
  description?: string
  fields?: CollectionField[]
  managed?: boolean
  isEdit?: boolean
  error?: string
  success?: string
  user?: {
    name: string
    email: string
    role: string
  }
  version?: string
  editorPlugins?: {
    tinymce: boolean
    quill: boolean
    easyMdx: boolean
  }
}

interface CollectionField {
  id: string
  field_name: string
  field_type: string
  field_label: string
  field_options: any
  field_order: number
  is_required: boolean
  is_searchable: boolean
}

interface CollectionsListPageData {
  collections: Collection[]
  search?: string
  showInternal?: boolean
  user?: {
    name: string
    email: string
    role: string
  }
  version?: string
}

type Bindings = {
  DB: D1Database
  CACHE_KV: KVNamespace
  MEDIA_BUCKET: R2Bucket
  ASSETS: Fetcher
  EMAIL_QUEUE?: Queue
  SENDGRID_API_KEY?: string
  DEFAULT_FROM_EMAIL?: string
  IMAGES_ACCOUNT_ID?: string
  IMAGES_API_TOKEN?: string
  ENVIRONMENT?: string
}

type Variables = {
  user?: {
    userId: string
    email: string
    role: string
    exp: number
    iat: number
  }
  requestId?: string
  startTime?: number
  appVersion?: string
}

export const adminCollectionsRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

adminCollectionsRoutes.use('*', requireAuth())

// ── List ─────────────────────────────────────────────────────────────────────

adminCollectionsRoutes.get('/', async (c) => {
  try {
    const user = c.get('user')
    const url = new URL(c.req.url)
    const search = url.searchParams.get('search') || ''
    const showInternal = url.searchParams.get('showInternal') === '1'

    // Build list from the in-memory registry + document_types (for any plugin-registered types
    // that were not registered via registerCollections but directly via DocumentTypeRegistry).
    const db = c.env.DB
    let results: any[] = []
    try {
      const stmt = db.prepare(
        "SELECT id, name, display_name, description, created_at, schema, source, queryable_fields, settings FROM document_types WHERE is_active = 1 ORDER BY created_at DESC"
      )
      const queryResults = await stmt.all()
      results = queryResults.results ?? []
    } catch (e) {
      // document_types may not exist in dev — fall through to code-only path.
    }

    // Code-defined collections from registry (source of truth for user collections).
    const codeCollections = getCollectionRegistry().list()
    const codeCollectionsMap = new Map(
      codeCollections.map((cfg) => {
        const fieldCount = cfg.schema?.properties ? Object.keys(cfg.schema.properties).length : 0
        return [cfg.name, {
          id: cfg.id,
          name: cfg.name,
          display_name: cfg.displayName,
          description: cfg.description,
          created_at: 0,
          formattedDate: 'Code-defined',
          field_count: fieldCount,
          managed: cfg.managed !== false,
          source_type: 'code',
          internal: isCodeCollectionInternal(cfg),
          versioning: cfg.versioning === true,
        } as Collection]
      })
    )

    // DB/document_type rows (system types from plugins, etc.)
    const dbCollections: Collection[] = results
      .filter((row: any) => row && row.id)
      .map((row: any) => {
        let fieldCount = 0
        if (row.schema) {
          try {
            const schema = typeof row.schema === 'string' ? JSON.parse(row.schema) : row.schema
            if (schema?.properties) fieldCount = Object.keys(schema.properties).length
          } catch {}
        }
        if (fieldCount === 0 && row.queryable_fields) {
          try {
            const qf = typeof row.queryable_fields === 'string' ? JSON.parse(row.queryable_fields) : row.queryable_fields
            if (Array.isArray(qf)) fieldCount = qf.length
          } catch {}
        }
        let dbVersioning = false
        if (row.settings) {
          try {
            const s = typeof row.settings === 'string' ? JSON.parse(row.settings) : row.settings
            dbVersioning = s?.versioning === true
          } catch {}
        }
        return {
          id: String(row.id || ''),
          name: String(row.name || ''),
          display_name: String(row.display_name || ''),
          description: row.description ? String(row.description) : undefined,
          created_at: Number(row.created_at || 0),
          formattedDate: row.created_at ? new Date(Number(row.created_at)).toLocaleDateString() : 'Unknown',
          field_count: fieldCount,
          managed: false,
          source_type: (row.source === 'code' || row.source === 'system' || row.source === 'plugin') ? 'code' : 'user',
          internal: isDbDocTypeInternal(row.source),
          versioning: dbVersioning,
        }
      })

    // Merge: code wins for same name.
    const mergedMap = new Map(codeCollectionsMap)
    dbCollections.forEach((col) => {
      const codeCol = codeCollectionsMap.get(col.name)
      mergedMap.set(col.name, codeCol ? {
        ...col,
        display_name: codeCol.display_name,
        description: codeCol.description,
        field_count: codeCol.field_count,
        managed: true,
        source_type: 'code',
        formattedDate: 'Code-defined',
        internal: codeCol.internal,
        versioning: codeCol.versioning ?? col.versioning,
      } : col)
    })

    let collections = Array.from(mergedMap.values())
    if (!showInternal) collections = collections.filter((c) => !c.internal)
    if (search) {
      const needle = search.toLowerCase()
      collections = collections.filter(
        (c) =>
          c.name.toLowerCase().includes(needle) ||
          c.display_name.toLowerCase().includes(needle) ||
          (c.description && c.description.toLowerCase().includes(needle))
      )
    }

    const pageData: CollectionsListPageData = {
      collections,
      search,
      showInternal,
      user: user ? { name: user.email, email: user.email, role: user.role } : undefined,
      version: c.get('appVersion'),
    }

    return c.html(renderCollectionsListPage(pageData))
  } catch (error) {
    console.error('Error fetching collections:', error)
    const errorMessage = error instanceof Error ? error.message : String(error)
    return c.html(html`<p>Error loading collections: ${errorMessage}</p>`)
  }
})

// ── New (instructional, no form) ─────────────────────────────────────────────

const DOCS_URL = 'https://sonicjs.com/collections'

adminCollectionsRoutes.get('/new', async (c) => {
  const user = c.get('user')
  const content = `
    <div class="max-w-3xl space-y-8">
      <div class="rounded-lg border border-cyan-500/30 bg-cyan-500/10 p-6">
        <div class="flex items-start gap-3">
          <svg class="h-6 w-6 text-cyan-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
          </svg>
          <div>
            <h2 class="text-lg font-semibold text-zinc-100">Collections are code-defined</h2>
            <p class="mt-2 text-sm text-zinc-300">
              SonicJS uses code-first collection definitions. Add a new collection by creating a
              <code class="rounded bg-zinc-800 px-1 py-0.5 text-cyan-400">.collection.ts</code>
              file and registering it via <code class="rounded bg-zinc-800 px-1 py-0.5 text-cyan-400">registerCollections()</code>.
            </p>
          </div>
        </div>
      </div>

      <div>
        <h3 class="text-base font-semibold text-zinc-100 mb-3">Quick start — app-level</h3>
        <ol class="space-y-3 text-sm text-zinc-300">
          <li class="flex gap-3">
            <span class="flex-shrink-0 w-6 h-6 rounded-full bg-zinc-800 text-cyan-400 text-xs font-semibold flex items-center justify-center">1</span>
            <span>Create <code class="rounded bg-zinc-800 px-1 py-0.5 text-cyan-400">src/collections/my-collection.collection.ts</code> exporting a <code class="rounded bg-zinc-800 px-1 py-0.5 text-cyan-400">CollectionConfig</code> default export.</span>
          </li>
          <li class="flex gap-3">
            <span class="flex-shrink-0 w-6 h-6 rounded-full bg-zinc-800 text-cyan-400 text-xs font-semibold flex items-center justify-center">2</span>
            <span>Import and register it in <code class="rounded bg-zinc-800 px-1 py-0.5 text-cyan-400">src/index.ts</code> using <code class="rounded bg-zinc-800 px-1 py-0.5 text-cyan-400">registerCollections([myCollection])</code>.</span>
          </li>
          <li class="flex gap-3">
            <span class="flex-shrink-0 w-6 h-6 rounded-full bg-zinc-800 text-cyan-400 text-xs font-semibold flex items-center justify-center">3</span>
            <span>Restart the dev server. The collection appears in the list and is available at <code class="rounded bg-zinc-800 px-1 py-0.5 text-cyan-400">/admin/content</code>.</span>
          </li>
        </ol>
      </div>

      <div>
        <h3 class="text-base font-semibold text-zinc-100 mb-3">Example</h3>
        <pre class="rounded-lg bg-zinc-950 border border-zinc-800 p-4 overflow-x-auto text-xs text-zinc-300"><code>// src/collections/products.collection.ts
import type { CollectionConfig } from '@sonicjs-cms/core'

const productsCollection: CollectionConfig = {
  name: 'products',
  displayName: 'Products',
  description: 'Catalog products',
  schema: {
    type: 'object',
    properties: {
      title: { type: 'string', title: 'Title', required: true },
      price: { type: 'number', title: 'Price', required: true },
      sku:   { type: 'string', title: 'SKU' },
    },
    required: ['title', 'price'],
  },
}

export default productsCollection</code></pre>
      </div>

      <div>
        <h3 class="text-base font-semibold text-zinc-100 mb-3">Then register it</h3>
        <pre class="rounded-lg bg-zinc-950 border border-zinc-800 p-4 overflow-x-auto text-xs text-zinc-300"><code>// src/index.ts
import { registerCollections } from '@sonicjs-cms/core'
import productsCollection from './collections/products.collection'

registerCollections([productsCollection])</code></pre>
      </div>

      <div class="rounded-lg border border-zinc-700 bg-zinc-900/30 p-5">
        <div class="flex items-start gap-3">
          <svg class="h-5 w-5 text-purple-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"/>
          </svg>
          <div>
            <h3 class="text-sm font-semibold text-zinc-100">Building a plugin?</h3>
            <p class="mt-1 text-sm text-zinc-400">
              Plugins can also register collections — call
              <code class="rounded bg-zinc-800 px-1 py-0.5 text-cyan-400">registerCollections([...])</code>
              inside your plugin's <code class="rounded bg-zinc-800 px-1 py-0.5 text-cyan-400">onBoot</code> handler.
              Collections registered by plugins appear in the list alongside app-defined ones.
            </p>
            <pre class="mt-3 rounded bg-zinc-950 border border-zinc-800 p-3 text-xs text-zinc-300 overflow-x-auto"><code>// my-plugin/index.ts
import { definePlugin, registerCollections } from '@sonicjs-cms/core'
import myCollection from './my-collection.collection'

export const myPlugin = definePlugin({
  name: 'my-plugin',
  async onBoot(ctx) {
    registerCollections([myCollection])
  },
})</code></pre>
          </div>
        </div>
      </div>

      <div class="flex flex-wrap gap-3 pt-2">
        <a href="${DOCS_URL}"
           target="_blank" rel="noopener"
           class="inline-flex items-center gap-2 rounded-md bg-cyan-500 px-4 py-2 text-sm font-medium text-zinc-950 hover:bg-cyan-400 transition-colors">
          Read the docs
          <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
          </svg>
        </a>
        <a href="/admin/collections"
           class="inline-flex items-center gap-2 rounded-md border border-zinc-700 bg-zinc-900 px-4 py-2 text-sm font-medium text-zinc-100 hover:bg-zinc-800 transition-colors">
          ← Back to collections
        </a>
      </div>
    </div>
  `

  const u = user as { email?: string; role?: string } | undefined
  return c.html(
    renderAdminLayoutCatalyst({
      title: 'Add a Collection',
      pageTitle: 'Add a Collection',
      currentPath: '/admin/collections',
      version: getCoreVersion(),
      user: u ? { name: u.email ?? 'Admin', email: u.email ?? '', role: u.role ?? 'admin' } : undefined,
      content,
    })
  )
})

// ── Detail (read-only) ────────────────────────────────────────────────────────

adminCollectionsRoutes.get('/:id', async (c) => {
  const db = c.env.DB
  try {
    const id = c.req.param('id')
    const user = c.get('user')

    // Look up via document_types first (has structured field data), fall back to registry.
    let collection: any = null
    try {
      const stmt = db.prepare('SELECT * FROM document_types WHERE id = ?')
      collection = await stmt.bind(id).first()
    } catch {}

    const registryRecord = getCollectionRegistry().getById(id) ?? getCollectionRegistry().getByName(id)

    if (!collection && !registryRecord) {
      const formData: CollectionFormData = {
        isEdit: true,
        error: 'Collection not found.',
        user: user ? { name: user.email, email: user.email, role: user.role } : undefined,
        version: c.get('appVersion'),
        editorPlugins: { tinymce: false, quill: false, easyMdx: false },
      }
      return c.html(renderCollectionFormPage(formData))
    }

    // Derive fields: prefer document_types schema, fall back to registry config.
    let fields: any[] = []
    let isCodeDriven = false

    if (collection?.schema) {
      try {
        const schema = typeof collection.schema === 'string' ? JSON.parse(collection.schema) : collection.schema
        if (schema?.properties) {
          let order = 0
          fields = Object.entries(schema.properties).map(([name, cfg]: [string, any]) => ({
            id: `schema-${name}`,
            field_name: name,
            field_type: cfg.enum ? 'select' : cfg.type === 'slug' || cfg.format === 'slug' ? 'slug' : cfg.format === 'richtext' ? 'richtext' : cfg.format === 'media' ? 'media' : cfg.format === 'date-time' ? 'date' : cfg.type || 'string',
            field_label: cfg.title || name,
            field_options: cfg,
            field_order: order++,
            is_required: cfg.required === true || !!(schema.required && (schema.required as string[]).includes(name)),
            is_searchable: cfg.searchable === true,
          }))
        }
      } catch {}
    }

    if (fields.length === 0 && registryRecord?.schema?.properties) {
      let order = 0
      fields = Object.entries(registryRecord.schema.properties).map(([name, cfg]: [string, any]) => ({
        id: `schema-${name}`,
        field_name: name,
        field_type: cfg.enum ? 'select' : cfg.type === 'slug' || cfg.format === 'slug' ? 'slug' : cfg.format === 'richtext' ? 'richtext' : cfg.format === 'media' ? 'media' : cfg.format === 'date-time' ? 'date' : cfg.type || 'string',
        field_label: cfg.title || name,
        field_options: cfg,
        field_order: order++,
        is_required: cfg.required === true || !!(registryRecord.schema.required && (registryRecord.schema.required as string[]).includes(name)),
        is_searchable: (cfg as any).searchable === true,
      }))
      isCodeDriven = true
    }

    const [tinymceActive, quillActive, mdxeditorActive] = await Promise.all([
      isPluginActive(db, 'tinymce-plugin'),
      isPluginActive(db, 'quill-editor'),
      isPluginActive(db, 'easy-mdx'),
    ])

    const displayName = collection?.display_name ?? registryRecord?.displayName ?? id
    const formData: CollectionFormData = {
      id: collection?.id ?? registryRecord?.id,
      name: collection?.name ?? registryRecord?.name,
      display_name: displayName,
      description: collection?.description ?? registryRecord?.description,
      fields,
      managed: collection?.managed === 1 || isCodeDriven || !!registryRecord,
      isEdit: true,
      user: user ? { name: user.email, email: user.email, role: user.role } : undefined,
      version: c.get('appVersion'),
      editorPlugins: { tinymce: tinymceActive, quill: quillActive, easyMdx: mdxeditorActive },
    }

    return c.html(renderCollectionFormPage(formData))
  } catch (error) {
    console.error('Error fetching collection:', error)
    const user = c.get('user')
    const [tinymceActive, quillActive, mdxeditorActive] = await Promise.all([
      isPluginActive(db, 'tinymce-plugin'),
      isPluginActive(db, 'quill-editor'),
      isPluginActive(db, 'easy-mdx'),
    ])
    const formData: CollectionFormData = {
      isEdit: true,
      error: 'Failed to load collection.',
      user: user ? { name: user.email, email: user.email, role: user.role } : undefined,
      version: c.get('appVersion'),
      editorPlugins: { tinymce: tinymceActive, quill: quillActive, easyMdx: mdxeditorActive },
    }
    return c.html(renderCollectionFormPage(formData))
  }
})
