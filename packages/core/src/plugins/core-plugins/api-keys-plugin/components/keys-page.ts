import { renderAdminLayoutCatalyst, AdminLayoutCatalystData } from '../../../../templates/layouts/admin-layout-catalyst.template'
import { escapeHtml } from '../../../../utils/sanitize'
import type { ApiKeySummary } from '../services/api-key-service'

interface BaseUser {
  name: string
  email: string
  role: string
}

export interface ApiKeysPageData {
  keys: ApiKeySummary[]
  user?: BaseUser
  version?: string
  dynamicMenuItems?: Array<{ label: string; path: string; icon: string }>
}

function fmtDate(ms: number | null): string {
  if (!ms) return '—'
  try {
    return new Date(ms).toISOString().slice(0, 10)
  } catch {
    return '—'
  }
}

function keyRow(k: ApiKeySummary): string {
  const name = escapeHtml(k.name)
  const prefix = escapeHtml(k.prefix)
  const id = escapeHtml(k.id)
  return `
    <tr class="border-t border-zinc-950/5 dark:border-white/10" data-key-id="${id}">
      <td class="py-3 pr-4 text-sm font-medium text-zinc-950 dark:text-white">${name}</td>
      <td class="py-3 pr-4 text-sm font-mono text-zinc-500 dark:text-zinc-400">${prefix}…</td>
      <td class="py-3 pr-4 text-sm text-zinc-500 dark:text-zinc-400">${fmtDate(k.createdAt ? k.createdAt * 1000 : null)}</td>
      <td class="py-3 pr-4 text-sm text-zinc-500 dark:text-zinc-400">${k.lastUsedAt ? fmtDate(k.lastUsedAt) : 'Never'}</td>
      <td class="py-3 pr-4 text-sm text-zinc-500 dark:text-zinc-400">${k.expiresAt ? fmtDate(k.expiresAt) : 'Never'}</td>
      <td class="py-3 text-right">
        <button type="button" onclick="revokeApiKey('${id}', '${name.replace(/'/g, "\\'")}')"
          class="rounded-lg bg-red-50 dark:bg-red-900/20 px-3 py-1.5 text-sm font-medium text-red-700 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-900/40 ring-1 ring-red-200 dark:ring-red-800 transition-colors">
          Revoke
        </button>
      </td>
    </tr>`
}

export function renderApiKeysPage(data: ApiKeysPageData): string {
  const { keys, user, version, dynamicMenuItems } = data

  const rows = keys.length
    ? keys.map(keyRow).join('')
    : `<tr><td colspan="6" class="py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">No API keys yet. Create one to enable programmatic access.</td></tr>`

  const content = `
    <div>
      <div class="sm:flex sm:items-center sm:justify-between mb-6">
        <div class="sm:flex-auto">
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">API Keys</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">
            Long-lived secrets for headless / server-to-server REST access. Send a key as the
            <code class="font-mono">x-api-key</code> header or <code class="font-mono">Authorization: Bearer &lt;key&gt;</code>.
            The secret is shown once at creation — store it now.
          </p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16">
          <button type="button" onclick="document.getElementById('create-key-modal').classList.remove('hidden')"
            class="inline-flex items-center justify-center rounded-lg bg-cyan-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-cyan-500 transition-colors shadow-sm">
            Create API key
          </button>
        </div>
      </div>

      <!-- Newly-created secret banner (populated by JS, shown once) -->
      <div id="new-key-banner" class="hidden mb-6 rounded-xl bg-emerald-50 dark:bg-emerald-900/20 p-4 ring-1 ring-emerald-200 dark:ring-emerald-800">
        <p class="text-sm font-medium text-emerald-800 dark:text-emerald-300 mb-2">
          Copy your new key now — it will not be shown again.
        </p>
        <div class="flex items-center gap-2">
          <code id="new-key-value" class="flex-1 rounded-lg bg-white dark:bg-zinc-900 px-3 py-2 text-sm font-mono text-zinc-950 dark:text-white ring-1 ring-zinc-950/10 dark:ring-white/10 break-all"></code>
          <button type="button" onclick="copyNewKey()"
            class="rounded-lg bg-emerald-600 px-3 py-2 text-sm font-semibold text-white hover:bg-emerald-500 transition-colors">
            Copy
          </button>
        </div>
      </div>

      <div class="rounded-xl bg-white/80 dark:bg-zinc-900/80 backdrop-blur-xl p-6 ring-1 ring-zinc-950/5 dark:ring-white/10 shadow-sm overflow-x-auto">
        <table class="w-full text-left">
          <thead>
            <tr class="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
              <th class="pb-2 pr-4">Name</th>
              <th class="pb-2 pr-4">Prefix</th>
              <th class="pb-2 pr-4">Created</th>
              <th class="pb-2 pr-4">Last used</th>
              <th class="pb-2 pr-4">Expires</th>
              <th class="pb-2 text-right">Actions</th>
            </tr>
          </thead>
          <tbody id="keys-tbody">${rows}</tbody>
        </table>
      </div>
    </div>

    <!-- Create modal -->
    <div id="create-key-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div class="w-full max-w-md rounded-xl bg-white dark:bg-zinc-900 p-6 ring-1 ring-zinc-950/10 dark:ring-white/10 shadow-xl">
        <h2 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Create API key</h2>
        <label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Name</label>
        <input id="new-key-name" type="text" placeholder="e.g. CI deploy token"
          class="w-full rounded-lg border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white mb-4 ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10">
        <label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Expires in (days, optional)</label>
        <input id="new-key-expiry" type="number" min="1" max="3650" placeholder="Never"
          class="w-full rounded-lg border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white mb-4 ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10">
        <div class="flex justify-end gap-2">
          <button type="button" onclick="document.getElementById('create-key-modal').classList.add('hidden')"
            class="rounded-lg bg-white dark:bg-zinc-800 px-4 py-2 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10">
            Cancel
          </button>
          <button type="button" onclick="createApiKey()"
            class="rounded-lg bg-cyan-600 px-4 py-2 text-sm font-semibold text-white hover:bg-cyan-500 transition-colors">
            Create
          </button>
        </div>
      </div>
    </div>

    <script>
      // CSRF: the csrf_token cookie is JS-readable (httpOnly:false); echo it back
      // as X-CSRF-Token on state-changing requests (signed double-submit).
      function csrfHeader() {
        const m = document.cookie.match(/(?:^|; )csrf_token=([^;]+)/)
        return m ? { 'X-CSRF-Token': decodeURIComponent(m[1]) } : {}
      }
      async function createApiKey() {
        const name = document.getElementById('new-key-name').value.trim()
        if (!name) { window.showNotification && window.showNotification('Name is required', 'error'); return }
        const expiry = parseInt(document.getElementById('new-key-expiry').value, 10)
        const body = { name }
        if (Number.isFinite(expiry) && expiry > 0) body.expiresInDays = expiry
        const res = await fetch('/admin/plugins/api-keys/api/keys', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...csrfHeader() },
          body: JSON.stringify(body),
        })
        if (!res.ok) {
          const e = await res.json().catch(() => ({}))
          window.showNotification && window.showNotification(e.error || 'Failed to create key', 'error')
          return
        }
        const { apiKey } = await res.json()
        document.getElementById('create-key-modal').classList.add('hidden')
        document.getElementById('new-key-value').textContent = apiKey.key
        document.getElementById('new-key-banner').classList.remove('hidden')
        setTimeout(() => location.reload(), 1500)
      }
      function copyNewKey() {
        const v = document.getElementById('new-key-value').textContent
        navigator.clipboard.writeText(v).then(() => window.showNotification && window.showNotification('Copied', 'success'))
      }
      async function revokeApiKey(id, name) {
        if (!confirm('Revoke "' + name + '"? This cannot be undone and will break any client using it.')) return
        const res = await fetch('/admin/plugins/api-keys/api/keys/' + id, { method: 'DELETE', headers: { ...csrfHeader() } })
        if (res.ok) {
          const row = document.querySelector('[data-key-id="' + id + '"]')
          if (row) row.remove()
          window.showNotification && window.showNotification('Key revoked', 'success')
        } else {
          window.showNotification && window.showNotification('Failed to revoke', 'error')
        }
      }
    </script>`

  const layoutData: AdminLayoutCatalystData = {
    title: 'API Keys',
    pageTitle: 'API Keys',
    currentPath: '/admin/plugins/api-keys',
    user,
    content,
    version,
    dynamicMenuItems,
  }

  return renderAdminLayoutCatalyst(layoutData)
}
