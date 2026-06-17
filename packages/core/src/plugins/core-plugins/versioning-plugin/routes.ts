/**
 * Versioning Plugin Routes
 *
 * GET  /admin/versioning/:rootId                       — render version history panel (HTML fragment)
 * POST /admin/versioning/:rootId/restore/:versionNumber — restore an older version as a new draft
 */

import { Hono } from 'hono'
import { requireAuth, requireRole } from '../../../middleware/auth'
import type { Bindings, Variables } from '../../../app'
import { DocumentRepository } from '../../../services/document-repository'
import { DocumentsService } from '../../../services/documents'
import { resolveDocScope, denyIfNotAllowed } from '../../../routes/admin-documents'
import { escapeHtml } from '../../../utils/sanitize'

const routes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

routes.use('*', requireAuth())
routes.use('*', requireRole(['admin', 'editor']))

// ─── GET /:rootId — version history panel ────────────────────────────────────
routes.get('/:rootId', async (c) => {
  const { rootId } = c.req.param()
  const db = c.env.DB

  const scope = await resolveDocScope(c, db, { rootId })
  if (!scope) {
    return c.html('<p class="text-zinc-500 dark:text-zinc-400 p-4">Document not found.</p>', 404)
  }

  if (!scope.docType?.settings?.versioning) {
    return c.html('<p class="text-zinc-500 dark:text-zinc-400 p-4">Versioning not enabled for this type.</p>', 404)
  }

  const denied = await denyIfNotAllowed(c, db, rootId, 'read', scope.docType?.settings, scope.tenantId)
  if (denied) return denied as any

  const repo = new DocumentRepository(db, scope.tenantId)
  const versions = await repo.getVersionHistory(rootId)

  // Safe for embedding inside a single-quoted JS string in a double-quoted HTML attribute:
  // escapeHtml converts ' → &#039; so no quote can break out of the attribute.
  const safeRootIdAttr = escapeHtml(rootId)

  const rows = versions.map((v) => {
    const isCurrentDraft = v.isCurrentDraft
    const isPublished = v.isPublished
    const dateStr = escapeHtml(new Date(v.updatedAt * 1000).toLocaleString())
    const updatedBy = escapeHtml(String(v.updatedBy ?? v.createdBy ?? 'System'))
    const vNum = escapeHtml(String(v.versionNumber))
    const vId = escapeHtml(String(v.id))

    const badges = [
      isCurrentDraft ? '<span class="inline-flex items-center rounded-md bg-blue-400/10 px-2 py-1 text-xs font-medium text-blue-400 ring-1 ring-inset ring-blue-400/20">Current Draft</span>' : '',
      isPublished ? '<span class="inline-flex items-center rounded-md bg-green-400/10 px-2 py-1 text-xs font-medium text-green-400 ring-1 ring-inset ring-green-400/20">Published</span>' : '',
    ].filter(Boolean).join(' ')

    // rootId is nanoid-charset and vNum is numeric (both safe inside a single-quoted JS string
    // within a double-quoted HTML attribute). Do NOT use JSON.stringify here — it emits double
    // quotes that would terminate the double-quoted onclick attribute and break the handler.
    const restoreButton = !isCurrentDraft
      ? `<button
           type="button"
           onclick="versioningRestore('${safeRootIdAttr}', '${vNum}')"
           class="inline-flex items-center gap-x-1 rounded-md bg-zinc-800 px-2.5 py-1.5 text-xs font-medium text-white shadow-sm hover:bg-zinc-700 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-zinc-600 transition-colors"
         >Restore</button>`
      : ''

    return `<tr class="border-t border-zinc-800">
      <td class="py-3 px-4 text-sm text-zinc-300">v${vNum}</td>
      <td class="py-3 px-4 text-sm text-zinc-400">${dateStr}</td>
      <td class="py-3 px-4 text-sm text-zinc-400">${updatedBy}</td>
      <td class="py-3 px-4">${badges}</td>
      <td class="py-3 px-4 text-right">${restoreButton}</td>
    </tr>`
  }).join('\n')

  const safeRootId = escapeHtml(rootId)

  const html = `
<div class="rounded-xl bg-zinc-900 ring-1 ring-white/10 shadow-2xl w-full max-w-2xl mx-auto overflow-hidden" style="min-width:480px">
  <div class="flex items-center justify-between px-6 py-4 border-b border-zinc-800">
    <h2 class="text-base font-semibold text-white flex items-center gap-2">
      <svg class="h-5 w-5 text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
        <path stroke-linecap="round" stroke-linejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z"/>
      </svg>
      Version History
    </h2>
    <button
      type="button"
      onclick="this.closest('.fixed') ? this.closest('.fixed').remove() : this.closest('[data-versioning-modal]')?.remove()"
      class="rounded-md p-1.5 text-zinc-400 hover:text-white hover:bg-zinc-800 transition-colors"
      aria-label="Close"
    >
      <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
        <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
      </svg>
    </button>
  </div>
  <div class="overflow-auto" style="max-height:60vh">
    ${versions.length === 0
      ? '<p class="text-zinc-400 text-sm p-6">No version history found.</p>'
      : `<table class="w-full text-left">
          <thead>
            <tr class="border-b border-zinc-800">
              <th class="py-2 px-4 text-xs font-medium text-zinc-500 uppercase tracking-wide">Version</th>
              <th class="py-2 px-4 text-xs font-medium text-zinc-500 uppercase tracking-wide">Date</th>
              <th class="py-2 px-4 text-xs font-medium text-zinc-500 uppercase tracking-wide">Author</th>
              <th class="py-2 px-4 text-xs font-medium text-zinc-500 uppercase tracking-wide">Status</th>
              <th class="py-2 px-4 text-xs font-medium text-zinc-500 uppercase tracking-wide text-right">Actions</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>`
    }
  </div>
  <div id="versioning-restore-status" class="px-6 py-3 text-sm hidden"></div>
</div>
<script>
  async function versioningRestore(rootId, versionNumber) {
    const statusEl = document.getElementById('versioning-restore-status');
    statusEl.className = 'px-6 py-3 text-sm text-zinc-400';
    statusEl.textContent = 'Restoring...';
    try {
      const res = await fetch('/admin/versioning/' + encodeURIComponent(rootId) + '/restore/' + encodeURIComponent(versionNumber), { method: 'POST' });
      const json = await res.json();
      if (res.ok && json.success) {
        statusEl.className = 'px-6 py-3 text-sm text-green-400';
        statusEl.textContent = 'Restored successfully. Reloading...';
        setTimeout(() => window.location.reload(), 800);
      } else {
        statusEl.className = 'px-6 py-3 text-sm text-red-400';
        statusEl.textContent = 'Restore failed: ' + (json.error || 'Unknown error');
      }
    } catch (e) {
      statusEl.className = 'px-6 py-3 text-sm text-red-400';
      statusEl.textContent = 'Restore failed: ' + String(e);
    }
  }
</script>
`

  return c.html(html)
})

// ─── POST /:rootId/restore/:versionNumber — restore a version as new draft ───
routes.post('/:rootId/restore/:versionNumber', async (c) => {
  const { rootId, versionNumber } = c.req.param()
  const db = c.env.DB
  const user = c.get('user') as any

  const scope = await resolveDocScope(c, db, { rootId })
  if (!scope) {
    return c.json({ error: 'Document not found' }, 404)
  }

  if (!scope.docType?.settings?.versioning) {
    return c.json({ error: 'Versioning not enabled for this type' }, 404)
  }

  const denied = await denyIfNotAllowed(c, db, rootId, 'update', scope.docType?.settings, scope.tenantId)
  if (denied) return denied as any

  // Load the specific version row (R3: tenant-scoped)
  const row = await db
    .prepare('SELECT * FROM documents WHERE root_id = ? AND tenant_id = ? AND version_number = ? LIMIT 1')
    .bind(rootId, scope.tenantId, Number(versionNumber))
    .first() as any

  if (!row) {
    return c.json({ error: `Version ${versionNumber} not found` }, 404)
  }

  const data = row.data ? JSON.parse(row.data) : {}
  const title: string | null = row.title ?? null
  const slug: string | null = row.slug ?? null

  const docType = scope.docType
  const svc = new DocumentsService(db, {
    queryableFields: docType?.queryableFields ?? [],
    typeSchemaVersion: docType?.schemaVersion ?? 1,
    maxVersionsPerRoot: docType?.settings?.maxVersionsPerRoot ?? 50,
    tenantId: scope.tenantId,
    versioning: docType?.settings?.versioning ?? false,
  })

  await svc.saveDraft(rootId, { data, title, slug }, user?.userId)

  return c.json({ success: true })
})

export default routes
