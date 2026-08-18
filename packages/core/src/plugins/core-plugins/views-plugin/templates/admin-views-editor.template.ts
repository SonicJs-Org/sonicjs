import { renderAdminLayoutCatalyst, type AdminLayoutCatalystData } from '../../../../templates/layouts/admin-layout-catalyst.template'
import { escapeHtml } from '../../../../utils/sanitize'

export interface CollectionOption {
  id: string
  name: string
  display_name: string
}

export interface ViewEditorData {
  id?: string
  name?: string
  display_name?: string
  description?: string
  collection_id?: string
  filter_config?: string | null
  sort_config?: string | null
  columns_config?: string | null
  page_size?: number
  is_public?: boolean
  isEdit: boolean
  collections: CollectionOption[]
  error?: string
  success?: string
  user?: { name: string; email: string; role: string }
  version?: string
}

/** JSON for a `<script>` context: `escapeHtml` is wrong here (it entity-encodes into JS), and
 *  raw `JSON.stringify` lets a value containing `</script>` close the block and execute in the
 *  admin's browser (stored XSS via e.g. a document-type display_name — the #1135 class).
 *  Escaping every `<` as `\\u003c` is a JSON-level no-op that makes breakout impossible. */
function jsonForScript(value: unknown): string {
  return JSON.stringify(value).replace(/</g, '\\u003c')
}

export function renderViewEditorPage(data: ViewEditorData): string {
  const isEdit = data.isEdit
  const _formAction = isEdit ? `/admin/views/api/${data.id}` : '/admin/views/api'
  const _formMethod = isEdit ? 'PUT' : 'POST'

  const collectionsJson = jsonForScript(data.collections.map(c => ({
    id: c.id,
    name: c.name,
    display_name: c.display_name,
  })))

  const content = `
    <div class="mx-auto max-w-7xl">
      <!-- Header -->
      <div class="mb-8 sm:flex sm:items-end sm:justify-between">
        <div>
          <a href="/admin/views" class="text-sm text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200">
            &larr; Back to Views
          </a>
          <h1 class="mt-2 text-2xl font-bold text-zinc-950 dark:text-white">
            ${isEdit ? `Edit View: ${escapeHtml(data.display_name || data.name || '')}` : 'New View'}
          </h1>
        </div>
        ${isEdit && data.id ? `
          <a href="/admin/views/${encodeURIComponent(data.id)}/display"
             class="mt-4 sm:mt-0 inline-flex items-center rounded-md px-3 py-2 text-sm font-semibold text-cyan-700 dark:text-cyan-300 ring-1 ring-inset ring-cyan-300 dark:ring-cyan-700 hover:bg-cyan-50 dark:hover:bg-cyan-900/30">
            Open display
          </a>
        ` : ''}
      </div>

      ${data.error ? `
        <div class="mb-6 rounded-md bg-red-50 dark:bg-red-900/20 p-4">
          <p class="text-sm text-red-700 dark:text-red-300">${escapeHtml(data.error)}</p>
        </div>
      ` : ''}

      ${data.success ? `
        <div class="mb-6 rounded-md bg-green-50 dark:bg-green-900/20 p-4">
          <p class="text-sm text-green-700 dark:text-green-300">${escapeHtml(data.success)}</p>
        </div>
      ` : ''}

      <div id="form-messages"></div>

      <!-- Split layout: config left, preview right -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <!-- Config Panel -->
        <div class="space-y-6">
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
            <div class="border-b border-zinc-200 dark:border-zinc-700 px-6 py-4">
              <h2 class="text-base font-semibold text-zinc-950 dark:text-white">Configuration</h2>
            </div>
            <div class="p-6 space-y-5">
              <!-- Name -->
              <div>
                <label for="view-name" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Name</label>
                <input type="text" id="view-name" name="name"
                  value="${escapeHtml(data.name || '')}"
                  ${isEdit ? 'readonly' : ''}
                  pattern="[a-z0-9][a-z0-9_-]*"
                  placeholder="e.g. active-products"
                  class="mt-1 block w-full rounded-md border border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-900 dark:text-zinc-100 shadow-sm focus:border-cyan-500 focus:ring-cyan-500 ${isEdit ? 'bg-zinc-50 dark:bg-zinc-800/50 text-zinc-500' : ''}" />
                <p class="mt-1 text-xs text-zinc-400">Lowercase, hyphens, underscores. Used in API URL: /api/views/<strong>name</strong></p>
              </div>

              <!-- Display Name -->
              <div>
                <label for="view-display-name" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Display Name</label>
                <input type="text" id="view-display-name" name="display_name"
                  value="${escapeHtml(data.display_name || '')}"
                  placeholder="e.g. Active Products"
                  class="mt-1 block w-full rounded-md border border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-900 dark:text-zinc-100 shadow-sm focus:border-cyan-500 focus:ring-cyan-500" />
                <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">Human-readable name shown in the admin panel and API responses.</p>
              </div>

              <!-- Description -->
              <div>
                <label for="view-description" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Description</label>
                <textarea id="view-description" name="description" rows="2"
                  placeholder="What this view returns..."
                  class="mt-1 block w-full rounded-md border border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-900 dark:text-zinc-100 shadow-sm focus:border-cyan-500 focus:ring-cyan-500">${escapeHtml(data.description || '')}</textarea>
                <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">Optional. Shown in the Views list.</p>
              </div>

              <!-- Collection -->
              <div>
                <label for="view-collection" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Collection</label>
                <select id="view-collection" name="collection_id"
                  class="mt-1 block w-full rounded-md border border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-900 dark:text-zinc-100 shadow-sm focus:border-cyan-500 focus:ring-cyan-500">
                  <option value="">Select a collection...</option>
                  ${data.collections.map(c => `
                    <option value="${escapeHtml(c.id)}" ${c.id === data.collection_id ? 'selected' : ''}>
                      ${escapeHtml(c.display_name || c.name)}
                    </option>
                  `).join('')}
                </select>
                <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">The collection this view queries. Cannot be changed after creation.</p>
              </div>

              <!-- Page Size -->
              <div>
                <label for="view-page-size" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Page Size</label>
                <input type="number" id="view-page-size" name="page_size"
                  value="${data.page_size || 25}" min="1" max="100"
                  class="mt-1 block w-32 rounded-md border border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-900 dark:text-zinc-100 shadow-sm focus:border-cyan-500 focus:ring-cyan-500" />
                <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">Rows per page (1–100, default 25). Override at query time with ?limit=N</p>
              </div>

              <!-- Public API toggle -->
              <div class="rounded-lg border border-zinc-200 dark:border-zinc-700 p-4">
                <label for="view-is-public" class="flex items-start gap-3 cursor-pointer">
                  <input type="checkbox" id="view-is-public" name="is_public" ${data.is_public ? 'checked' : ''}
                    class="mt-0.5 h-4 w-4 rounded border-zinc-300 dark:border-zinc-600 text-cyan-600 focus:ring-cyan-500" />
                  <span>
                    <span class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Public API</span>
                    <span class="block mt-1 text-xs text-zinc-500 dark:text-zinc-400">Off by default. When on, <code class="text-cyan-700 dark:text-cyan-300">GET /api/views/<strong>name</strong></code> serves this view's <strong>published</strong> rows to anyone — but only if the collection itself allows public read. Leave off to keep the view admin-only.</span>
                  </span>
                </label>
              </div>

              <!-- Filters (visual builder — Views MVP PR-5a) -->
              <div>
                <label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Filters</label>
                <p class="mt-0.5 mb-2 text-xs text-zinc-500 dark:text-zinc-400">Top-level rules must all match (AND). Add a condition group to match ANY/ALL of a set (OR). Pick a collection first to choose fields.</p>
                <div id="filter-builder" class="space-y-2"></div>
                <button type="button" id="add-filter-btn"
                  class="mt-2 inline-flex items-center gap-1 rounded-md border border-dashed border-zinc-300 dark:border-zinc-600 px-3 py-1.5 text-sm text-zinc-600 dark:text-zinc-300 hover:border-cyan-500 hover:text-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed">
                  <span class="text-base leading-none">+</span> Add filter
                </button>
                <!-- OR condition groups (Views Phase-2 OR-logic, PR-2) -->
                <div id="filter-groups" class="space-y-3 mt-3"></div>
                <button type="button" id="add-group-btn"
                  class="mt-2 inline-flex items-center gap-1 rounded-md border border-dashed border-zinc-300 dark:border-zinc-600 px-3 py-1.5 text-sm text-zinc-600 dark:text-zinc-300 hover:border-cyan-500 hover:text-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed">
                  <span class="text-base leading-none">+</span> Add condition group (OR)
                </button>
                <details class="mt-3">
                  <summary class="text-xs text-zinc-500 dark:text-zinc-400 cursor-pointer hover:text-zinc-700 dark:hover:text-zinc-300">Advanced: edit raw JSON</summary>
                  <textarea id="view-filter-config" name="filter_config" rows="4"
                    placeholder='{"rules": [{"field": "status", "operator": "_eq", "value": "published"}]}'
                    class="mt-1 block w-full rounded-md border border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-mono text-zinc-900 dark:text-zinc-100 shadow-sm focus:border-cyan-500 focus:ring-cyan-500">${escapeHtml(formatJson(data.filter_config))}</textarea>
                  <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">The builder writes this on every change. Editing raw JSON here is for power users; re-open the page to rebuild the visual rows from it.</p>
                </details>
              </div>

              <!-- Sort (visual builder — Views MVP PR-5c) -->
              <div>
                <label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Sort</label>
                <p class="mt-0.5 mb-2 text-xs text-zinc-500 dark:text-zinc-400">Applied in order.</p>
                <div id="sort-builder" class="space-y-2"></div>
                <button type="button" id="add-sort-btn"
                  class="mt-2 inline-flex items-center gap-1 rounded-md border border-dashed border-zinc-300 dark:border-zinc-600 px-3 py-1.5 text-sm text-zinc-600 dark:text-zinc-300 hover:border-cyan-500 hover:text-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed">
                  <span class="text-base leading-none">+</span> Add sort
                </button>
                <details class="mt-3">
                  <summary class="text-xs text-zinc-500 dark:text-zinc-400 cursor-pointer hover:text-zinc-700 dark:hover:text-zinc-300">Advanced: edit raw JSON</summary>
                  <textarea id="view-sort-config" name="sort_config" rows="2"
                    placeholder='[{"field": "created_at", "direction": "desc"}]'
                    class="mt-1 block w-full rounded-md border border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-mono text-zinc-900 dark:text-zinc-100 shadow-sm focus:border-cyan-500 focus:ring-cyan-500">${escapeHtml(formatJson(data.sort_config))}</textarea>
                </details>
              </div>

              <!-- Columns (visual picker — Views MVP PR-5c) -->
              <div>
                <label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Columns <span class="text-xs text-zinc-400">(none checked = all)</span></label>
                <p class="mt-0.5 mb-2 text-xs text-zinc-500 dark:text-zinc-400">Pick which fields the view returns. System columns are always included.</p>
                <div id="columns-builder" class="flex flex-wrap gap-x-4 gap-y-1.5"></div>
                <details class="mt-3">
                  <summary class="text-xs text-zinc-500 dark:text-zinc-400 cursor-pointer hover:text-zinc-700 dark:hover:text-zinc-300">Advanced: edit raw JSON</summary>
                  <textarea id="view-columns-config" name="columns_config" rows="2"
                    placeholder='{"fields": ["title", "price", "status"]}'
                    class="mt-1 block w-full rounded-md border border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-mono text-zinc-900 dark:text-zinc-100 shadow-sm focus:border-cyan-500 focus:ring-cyan-500">${escapeHtml(formatJson(data.columns_config))}</textarea>
                </details>
              </div>

              <!-- Submit -->
              <div class="flex items-center gap-3 pt-2">
                <button type="button" id="save-view-btn"
                  class="inline-flex items-center rounded-md bg-cyan-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-cyan-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-600">
                  ${isEdit ? 'Update View' : 'Create View'}
                </button>
                ${isEdit ? `
                  <button type="button" id="delete-view-btn"
                    class="inline-flex items-center rounded-md bg-red-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-red-500">
                    Delete
                  </button>
                ` : ''}
              </div>
            </div>
          </div>
        </div>

        <!-- Preview Panel -->
        <div class="space-y-6">
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
            <div class="border-b border-zinc-200 dark:border-zinc-700 px-6 py-4 flex items-center justify-between">
              <h2 class="text-base font-semibold text-zinc-950 dark:text-white">Live Preview</h2>
              <div class="flex items-center gap-2">
                <button type="button" id="preview-mode-table"
                  class="px-3 py-1 text-xs rounded font-medium bg-cyan-600 text-white">
                  Table
                </button>
                <button type="button" id="preview-mode-json"
                  class="px-3 py-1 text-xs rounded font-medium bg-zinc-200 text-zinc-600 dark:bg-zinc-700 dark:text-zinc-300">
                  JSON
                </button>
                <button type="button" id="refresh-preview-btn"
                  class="text-xs text-cyan-600 dark:text-cyan-400 hover:underline ml-2">
                  Refresh
                </button>
              </div>
            </div>
            <div class="p-6">
              ${isEdit && data.name ? `
                <div class="mb-4">
                  <span class="text-xs text-zinc-400 font-mono">GET /api/views/${escapeHtml(data.name)}</span>
                </div>
              ` : `
                <p class="text-sm text-zinc-400">Live preview of the current filters — no save needed.</p>
              `}
              <div id="preview-container">
                <div id="preview-loading" class="${isEdit && data.name ? '' : 'hidden'} text-sm text-zinc-400">Loading...</div>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>

    <script>
      (function() {
        var isEdit = ${isEdit ? 'true' : 'false'};
        var viewId = ${data.id ? `'${escapeHtml(data.id)}'` : 'null'};
        var viewName = ${data.name ? `'${escapeHtml(data.name)}'` : 'null'};
        var collections = ${collectionsJson};

        // ── Preview state ─────────────────────────────────────────────
        var previewMode = localStorage.getItem('viewsPreviewMode') || 'table';
        var previewPage = 1;
        var lastPreviewData = null;

        // Apply initial toggle state
        updateToggleButtons();

        // ── Save handler ──────────────────────────────────────────────
        document.getElementById('save-view-btn')?.addEventListener('click', async function() {
          var msgEl = document.getElementById('form-messages');
          var name = document.getElementById('view-name').value.trim();
          var display_name = document.getElementById('view-display-name').value.trim();
          var description = document.getElementById('view-description').value.trim();
          var collection_id = document.getElementById('view-collection').value;
          var page_size = parseInt(document.getElementById('view-page-size').value, 10) || 25;
          var is_public = document.getElementById('view-is-public').checked;

          if (!name) { msgEl.innerHTML = '<div class="mb-4 rounded-md bg-red-50 dark:bg-red-900/20 p-4 text-sm text-red-700 dark:text-red-300">Name is required</div>'; return; }

          var filter_config = null, sort_config = null, columns_config = null;
          try {
            var fc = document.getElementById('view-filter-config').value.trim();
            if (fc) filter_config = JSON.parse(fc);
          } catch(e) { msgEl.innerHTML = '<div class="mb-4 rounded-md bg-red-50 dark:bg-red-900/20 p-4 text-sm text-red-700 dark:text-red-300">Invalid filter config JSON</div>'; return; }
          try {
            var sc = document.getElementById('view-sort-config').value.trim();
            if (sc) sort_config = JSON.parse(sc);
          } catch(e) { msgEl.innerHTML = '<div class="mb-4 rounded-md bg-red-50 dark:bg-red-900/20 p-4 text-sm text-red-700 dark:text-red-300">Invalid sort config JSON</div>'; return; }
          try {
            var cc = document.getElementById('view-columns-config').value.trim();
            if (cc) columns_config = JSON.parse(cc);
          } catch(e) { msgEl.innerHTML = '<div class="mb-4 rounded-md bg-red-50 dark:bg-red-900/20 p-4 text-sm text-red-700 dark:text-red-300">Invalid columns config JSON</div>'; return; }

          var url = isEdit ? '/admin/views/api/' + viewId : '/admin/views/api';
          var method = isEdit ? 'PUT' : 'POST';
          var body = { name: name, display_name: display_name || name, description: description || null, collection_id: collection_id || null, filter_config: filter_config, sort_config: sort_config, columns_config: columns_config, page_size: page_size, is_public: is_public };

          try {
            var res = await fetch(url, { method: method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
            var json = await res.json();
            if (!res.ok) {
              msgEl.innerHTML = '<div class="mb-4 rounded-md bg-red-50 dark:bg-red-900/20 p-4 text-sm text-red-700 dark:text-red-300">' + (json.error || 'Save failed') + '</div>';
              return;
            }
            if (!isEdit) {
              window.location.href = '/admin/views/' + json.id;
            } else {
              msgEl.innerHTML = '<div class="mb-4 rounded-md bg-green-50 dark:bg-green-900/20 p-4 text-sm text-green-700 dark:text-green-300">View updated</div>';
              previewPage = 1;
              loadPreview();
            }
          } catch(e) {
            msgEl.innerHTML = '<div class="mb-4 rounded-md bg-red-50 dark:bg-red-900/20 p-4 text-sm text-red-700 dark:text-red-300">Network error</div>';
          }
        });

        // ── Delete handler ────────────────────────────────────────────
        document.getElementById('delete-view-btn')?.addEventListener('click', async function() {
          if (!confirm('Delete this view?')) return;
          try {
            await fetch('/admin/views/api/' + viewId, { method: 'DELETE' });
            window.location.href = '/admin/views';
          } catch(e) {
            alert('Delete failed');
          }
        });

        // ── Preview loading ───────────────────────────────────────────
        // Build the in-progress draft config straight from the form (PR-5a / C1: live preview of an
        // UNSAVED view — no "save first" needed). *_config are JSON strings, the shape previewDraft wants.
        function buildDraft() {
          return {
            collection_id: document.getElementById('view-collection').value || null,
            filter_config: document.getElementById('view-filter-config').value.trim() || null,
            sort_config: document.getElementById('view-sort-config').value.trim() || null,
            columns_config: document.getElementById('view-columns-config').value.trim() || null,
            page_size: parseInt(document.getElementById('view-page-size').value, 10) || 25
          };
        }

        async function loadPreview() {
          var container = document.getElementById('preview-container');
          var draft = buildDraft();
          if (!draft.collection_id) {
            container.innerHTML = '<p class="text-sm text-zinc-400 dark:text-zinc-500 py-4">Pick a collection to see a live preview.</p>';
            return;
          }
          var loading = document.getElementById('preview-loading');
          if (loading) { loading.classList.remove('hidden'); }
          try {
            var res = await fetch('/admin/views/api/preview', {
              method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(draft)
            });
            var json = await res.json();
            if (!res.ok) {
              container.innerHTML = '<p class="text-sm text-red-500 py-4">' + esc(json.error || 'Preview failed') + '</p>';
              return;
            }
            lastPreviewData = json;
            renderPreview(json);
          } catch(e) {
            container.innerHTML = '<p class="text-sm text-red-500">Error loading preview: ' + esc(e.message) + '</p>';
          }
        }

        function renderPreview(data) {
          var container = document.getElementById('preview-container');
          if (previewMode === 'table') {
            container.innerHTML = renderPreviewTable(data);
          } else {
            container.innerHTML = '<pre class="text-xs font-mono bg-zinc-50 dark:bg-zinc-800 rounded-lg p-4 overflow-auto max-h-[32rem] text-zinc-700 dark:text-zinc-300">'
              + esc(JSON.stringify(data, null, 2)) + '</pre>';
          }
        }

        // ── Table renderer ────────────────────────────────────────────
        function renderPreviewTable(response) {
          var items = response.data || [];
          var meta = response.meta || {};

          if (items.length === 0) {
            return '<p class="text-zinc-500 dark:text-zinc-400 text-sm py-4">No results match the current filters.</p>';
          }

          // Determine columns
          var configuredCols = getConfiguredColumns();
          var allKeys = Object.keys(items[0]);
          var hiddenCols = { id: 1, created_by: 1, updated_by: 1 };
          var columns;
          if (configuredCols && configuredCols.length > 0) {
            columns = configuredCols;
          } else {
            columns = allKeys.filter(function(k) { return !hiddenCols[k]; });
          }

          // Table header
          var html = '<div class="overflow-x-auto">';
          html += '<table class="w-full text-sm">';
          html += '<thead><tr class="border-b border-zinc-200 dark:border-zinc-700">';
          for (var i = 0; i < columns.length; i++) {
            var label = columns[i].replace(/_/g, ' ').split(' ').map(function(w) { return w.charAt(0).toUpperCase() + w.slice(1); }).join(' ');
            html += '<th class="text-left py-2 px-3 text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider whitespace-nowrap">' + esc(label) + '</th>';
          }
          html += '</tr></thead>';

          // Table body
          html += '<tbody class="divide-y divide-zinc-100 dark:divide-zinc-800">';
          for (var r = 0; r < items.length; r++) {
            var item = items[r];
            var editUrl = item.id ? '/admin/content/edit?id=' + encodeURIComponent(item.id) + '&collection=' + encodeURIComponent(getCollectionName()) : '#';
            html += '<tr class="hover:bg-zinc-50 dark:hover:bg-zinc-800/50 cursor-pointer" onclick="window.location=\\'' + editUrl + '\\'">';
            for (var c = 0; c < columns.length; c++) {
              html += '<td class="py-2 px-3 text-zinc-700 dark:text-zinc-300 max-w-xs">' + formatValue(columns[c], item[columns[c]]) + '</td>';
            }
            html += '</tr>';
          }
          html += '</tbody></table></div>';

          // Footer
          var total = meta.total || items.length;
          var page = meta.page || 1;
          var pages = meta.pages || 1;
          html += '<div class="flex items-center justify-between mt-3 px-1">';
          html += '<p class="text-xs text-zinc-500 dark:text-zinc-400">';
          html += 'Showing ' + items.length + ' of ' + total + ' results';
          if (pages > 1) html += ' &middot; Page ' + page + ' of ' + pages;
          html += '</p>';
          if (pages > 1) {
            html += '<div class="flex items-center gap-2">';
            var prevDisabled = page <= 1;
            var nextDisabled = !meta.hasNext;
            html += '<button onclick="window.__viewsPreview.goPage(' + (page - 1) + ')" ' + (prevDisabled ? 'disabled' : '') + ' class="px-2 py-1 text-xs rounded ' + (prevDisabled ? 'text-zinc-400 dark:text-zinc-600 cursor-not-allowed' : 'text-zinc-600 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800') + '">&larr; Prev</button>';
            html += '<button onclick="window.__viewsPreview.goPage(' + (page + 1) + ')" ' + (nextDisabled ? 'disabled' : '') + ' class="px-2 py-1 text-xs rounded ' + (nextDisabled ? 'text-zinc-400 dark:text-zinc-600 cursor-not-allowed' : 'text-zinc-600 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800') + '">Next &rarr;</button>';
            html += '</div>';
          }
          html += '</div>';

          return html;
        }

        // ── Value formatter ───────────────────────────────────────────
        function formatValue(col, value) {
          if (value === null || value === undefined) return '<span class="text-zinc-400">&mdash;</span>';

          // Booleans
          if (value === true || value === 1) {
            if (col.startsWith('is_') || col === 'in_stock' || col === 'is_featured') {
              return '<span class="text-green-600 dark:text-green-400">&#10003;</span>';
            }
          }
          if (value === false) return '<span class="text-red-500 dark:text-red-400">&#10007;</span>';
          if (value === 0 && (col.startsWith('is_') || col === 'in_stock' || col === 'is_featured')) {
            return '<span class="text-red-500 dark:text-red-400">&#10007;</span>';
          }

          // Dates (Unix ms timestamps)
          if ((col.endsWith('_at') || col.endsWith('_date') || col === 'publish_date' || col === 'event_date' || col === 'start_date') && typeof value === 'number' && value > 1000000000000) {
            try { return esc(new Date(value).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })); }
            catch(e) { return esc(String(value)); }
          }

          // Currency
          if ((col === 'price' || col === 'cost' || col === 'amount') && typeof value === 'number') {
            return '$' + value.toFixed(2);
          }

          // HTML content — strip tags, truncate
          if (typeof value === 'string' && value.indexOf('<') !== -1) {
            var stripped = value.replace(/<[^>]*>/g, '').trim();
            return truncate(stripped, 80);
          }

          // Long strings
          if (typeof value === 'string' && value.length > 80) {
            return truncate(value, 80);
          }

          // JSON objects/arrays
          if (typeof value === 'object') {
            if (Array.isArray(value)) return '<span class="text-zinc-400">[' + value.length + ' items]</span>';
            return '<span class="text-zinc-400">{...}</span>';
          }

          return esc(String(value));
        }

        function truncate(str, max) {
          if (str.length <= max) return esc(str);
          return esc(str.substring(0, max)) + '<span class="text-zinc-400">&hellip;</span>';
        }

        // Client-side counterpart to utils/sanitize's escapeHtml (R8) — that helper runs
        // server-side only, so this dynamic filter-builder JS (which runs in the browser)
        // needs its own copy. Escapes the same five characters, including the single quote,
        // so it stays safe even if a future edit adds a single-quoted attribute.
        function esc(str) {
          if (!str) return '';
          return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
        }

        // ── Toggle logic ──────────────────────────────────────────────
        function setPreviewMode(mode) {
          previewMode = mode;
          localStorage.setItem('viewsPreviewMode', mode);
          updateToggleButtons();
          if (lastPreviewData) renderPreview(lastPreviewData);
        }

        function updateToggleButtons() {
          var tableBtn = document.getElementById('preview-mode-table');
          var jsonBtn = document.getElementById('preview-mode-json');
          if (!tableBtn || !jsonBtn) return;
          var activeClass = 'px-3 py-1 text-xs rounded font-medium bg-cyan-600 text-white';
          var inactiveClass = 'px-3 py-1 text-xs rounded font-medium bg-zinc-200 text-zinc-600 dark:bg-zinc-700 dark:text-zinc-300';
          tableBtn.className = previewMode === 'table' ? activeClass : inactiveClass;
          jsonBtn.className = previewMode === 'json' ? activeClass : inactiveClass;
        }

        // ── Helpers ───────────────────────────────────────────────────
        function getConfiguredColumns() {
          var textarea = document.getElementById('view-columns-config');
          if (!textarea || !textarea.value.trim()) return null;
          try {
            var config = JSON.parse(textarea.value);
            if (config && config.fields && Array.isArray(config.fields)) return config.fields;
            if (Array.isArray(config)) return config;
            return null;
          } catch(e) { return null; }
        }

        function getCollectionName() {
          var sel = document.getElementById('view-collection');
          if (!sel || !sel.value) return '';
          var match = collections.find(function(c) { return c.id === sel.value; });
          return match ? match.name : '';
        }

        function goPage(page) {
          if (page < 1) return;
          previewPage = page;
          loadPreview();
        }

        // ── Wire events ───────────────────────────────────────────────
        document.getElementById('preview-mode-table')?.addEventListener('click', function() { setPreviewMode('table'); });
        document.getElementById('preview-mode-json')?.addEventListener('click', function() { setPreviewMode('json'); });
        document.getElementById('refresh-preview-btn')?.addEventListener('click', function() { previewPage = 1; loadPreview(); });

        // ── Visual filter builder (PR-5a) ─────────────────────────────
        // viewColumns: [{ name, fieldType, handler, operators, enumOptions?, referenceTarget? }]
        var viewColumns = [];
        var previewTimer = null;
        var NO_VALUE_OPS = { '_null': 1 }; // operators that take no value input
        // Filter operators are raw grammar tokens (matches the query-param API, e.g.
        // ?filter[x][_gte]=10) — shown to editors as labels, with the token as a hover hint
        // so the two never drift apart.
        var OP_LABELS = {
          '_eq': 'equals', '_neq': 'not equal to', '_gt': 'greater than', '_gte': 'greater than or equal to',
          '_lt': 'less than', '_lte': 'less than or equal to', '_between': 'between',
          '_contains': 'contains', '_starts': 'starts with', '_in': 'is one of', '_null': 'is empty'
        };
        var OP_HINTS = {
          '_eq': '_eq — exact match', '_neq': '_neq — exact non-match', '_gt': '_gt', '_gte': '_gte',
          '_lt': '_lt', '_lte': '_lte',
          '_between': '_between — two comma-separated values, e.g. 10,20',
          '_contains': '_contains — substring match', '_starts': '_starts — prefix match',
          '_in': '_in — comma-separated list, e.g. a,b,c', '_null': '_null — field is empty/missing'
        };

        function colByName(name) { return viewColumns.find(function(c) { return c.name === name; }); }
        function debouncedPreview() {
          if (previewTimer) clearTimeout(previewTimer);
          previewTimer = setTimeout(function() { previewPage = 1; loadPreview(); }, 400);
        }

        var ctl = 'rounded-md border border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 px-2 py-1.5 text-sm text-zinc-900 dark:text-zinc-100';
        function fieldSelectHtml(selected) {
          var h = '<select class="fb-field ' + ctl + '">';
          if (viewColumns.length === 0) h += '<option value="">(pick a collection)</option>';
          viewColumns.forEach(function(c) { h += '<option value="' + esc(c.name) + '"' + (c.name === selected ? ' selected' : '') + '>' + esc(c.name) + '</option>'; });
          return h + '</select>';
        }
        function opSelectHtml(col, selected) {
          var ops = (col && col.operators) || [];
          var h = '<select class="fb-op ' + ctl + '" title="' + esc(OP_HINTS[selected] || selected) + '">';
          ops.forEach(function(op) {
            h += '<option value="' + esc(op) + '"' + (op === selected ? ' selected' : '')
              + ' title="' + esc(OP_HINTS[op] || op) + '">' + esc(OP_LABELS[op] || op) + '</option>';
          });
          return h + '</select>';
        }
        function valueInputHtml(col, op, value) {
          if (NO_VALUE_OPS[op]) return '<span class="fb-value text-xs text-zinc-400 px-2 py-1.5" data-novalue="1"></span>';
          var ft = col ? col.fieldType : '';
          if (ft === 'boolean' || ft === 'checkbox') {
            return '<select class="fb-value ' + ctl + '"><option value="true"' + (String(value) === 'true' ? ' selected' : '') + '>true</option><option value="false"' + (String(value) === 'false' ? ' selected' : '') + '>false</option></select>';
          }
          // PR-5b: labelled dropdown for select/radio/multiselect (PR-4's enumOptions). A blank
          // first option keeps an empty value available (and lets the placeholder read as "any").
          if (col && col.enumOptions && col.enumOptions.length) {
            var eh = '<select class="fb-value ' + ctl + '"><option value=""' + (value == null || value === '' ? ' selected' : '') + '>—</option>';
            col.enumOptions.forEach(function(o) {
              eh += '<option value="' + esc(o.value) + '"' + (String(value) === String(o.value) ? ' selected' : '') + '>' + esc(o.label) + '</option>';
            });
            return eh + '</select>';
          }
          // _in/_between take a comma-separated LIST of values — a native number/date input
          // can't hold "10,20", so both force a plain text box regardless of field type.
          var multi = op === '_in' || op === '_between';
          var type = multi ? 'text' : (col && col.handler === 'numeric' ? 'number' : (col && col.handler === 'date' ? 'date' : 'text'));
          // Reference/media fields keep a text input in PR-5b (a record picker needs a records
          // endpoint — a later slice); show the target collection as a hint placeholder.
          var ph = (col && col.referenceTarget && col.referenceTarget.length) ? (' placeholder="' + esc(col.referenceTarget.join(', ')) + ' id"')
            : op === '_between' ? ' placeholder="min,max — e.g. 10,20"'
            : op === '_in' ? ' placeholder="comma-separated — e.g. a,b,c"'
            : '';
          return '<input type="' + type + '" class="fb-value ' + ctl + '"' + ph + ' value="' + esc(value == null ? '' : String(value)) + '" />';
        }
        function makeRow(rule) {
          var field = (rule && rule.field) || (viewColumns[0] && viewColumns[0].name) || '';
          var col = colByName(field);
          var op = (rule && rule.operator) || (col && col.operators && col.operators[0]) || '_eq';
          var row = document.createElement('div');
          row.className = 'fb-row flex items-center gap-2';
          row.innerHTML = fieldSelectHtml(field) + opSelectHtml(col, op) + valueInputHtml(col, op, rule ? rule.value : '')
            + '<button type="button" class="fb-remove text-zinc-400 hover:text-red-500 px-1.5 text-lg leading-none" title="Remove">&times;</button>';
          return row;
        }
        function readRow(row) {
          var fieldEl = row.querySelector('.fb-field'); if (!fieldEl || !fieldEl.value) return null;
          var opEl = row.querySelector('.fb-op');
          var rule = { field: fieldEl.value, operator: opEl ? opEl.value : '_eq' };
          var valEl = row.querySelector('.fb-value');
          if (valEl && !valEl.getAttribute('data-novalue')) rule.value = valEl.value;
          return rule;
        }
        function readFilters() {
          var rules = [];
          document.querySelectorAll('#filter-builder .fb-row').forEach(function(row) { var r = readRow(row); if (r) rules.push(r); });
          return rules;
        }
        // OR groups: each group is { match:'and'|'or', rules:[...] }, AND-ed with the
        // top-level rules. Empty groups are dropped (the engine never emits '()').
        function readGroups() {
          var groups = [];
          document.querySelectorAll('#filter-groups .fb-group').forEach(function(g) {
            var matchEl = g.querySelector('.fbg-match');
            var match = matchEl && matchEl.value === 'and' ? 'and' : 'or';
            var rules = [];
            g.querySelectorAll('.fbg-rows .fb-row').forEach(function(row) { var r = readRow(row); if (r) rules.push(r); });
            if (rules.length) groups.push({ match: match, rules: rules });
          });
          return groups;
        }
        function syncFilters() {
          var rules = readFilters();
          var groups = readGroups();
          var out = null;
          if (groups.length) out = { rules: rules, groups: groups };
          else if (rules.length) out = { rules: rules };
          document.getElementById('view-filter-config').value = out ? JSON.stringify(out) : '';
          debouncedPreview();
        }
        function addFilterRow(rule) { document.getElementById('filter-builder').appendChild(makeRow(rule)); }
        // ── OR group builder (Views Phase-2 OR-logic, PR-2) ───────────
        function matchSelectHtml(match) {
          return '<select class="fbg-match ' + ctl + '">'
            + '<option value="or"' + (match !== 'and' ? ' selected' : '') + '>ANY (OR)</option>'
            + '<option value="and"' + (match === 'and' ? ' selected' : '') + '>ALL (AND)</option>'
            + '</select>';
        }
        function addGroup(group) {
          var el = document.createElement('div');
          el.className = 'fb-group rounded-md border border-zinc-200 dark:border-zinc-700 p-3 space-y-2';
          el.innerHTML = '<div class="flex items-center gap-2">'
            + '<span class="text-xs text-zinc-500 dark:text-zinc-400">Match</span>' + matchSelectHtml(group && group.match)
            + '<span class="text-xs text-zinc-500 dark:text-zinc-400">of these conditions:</span>'
            + '<button type="button" class="fbg-remove-group text-zinc-400 hover:text-red-500 px-1.5 text-xs ml-auto" title="Remove group">Remove group</button>'
            + '</div><div class="fbg-rows space-y-2"></div>'
            + '<button type="button" class="fbg-add-cond inline-flex items-center gap-1 rounded-md border border-dashed border-zinc-300 dark:border-zinc-600 px-2 py-1 text-xs text-zinc-600 dark:text-zinc-300 hover:border-cyan-500 hover:text-cyan-600"><span class="text-base leading-none">+</span> Add condition</button>';
          document.getElementById('filter-groups').appendChild(el);
          var rowsHost = el.querySelector('.fbg-rows');
          var seed = (group && Array.isArray(group.rules) && group.rules.length) ? group.rules : [null];
          seed.forEach(function(r) { rowsHost.appendChild(makeRow(r)); });
        }

        // Row field/op change → rebuild that row's op + value widgets. Shared by the
        // top-level builder and OR groups (operates on any .fb-row).
        function onRowChange(e) {
          var row = e.target.closest('.fb-row'); if (!row) return;
          if (e.target.classList.contains('fb-field')) {
            var col = colByName(row.querySelector('.fb-field').value);
            var op = (col && col.operators && col.operators[0]) || '_eq';
            row.querySelector('.fb-op').outerHTML = opSelectHtml(col, op);
            row.querySelector('.fb-value').outerHTML = valueInputHtml(col, op, '');
          } else if (e.target.classList.contains('fb-op')) {
            var c2 = colByName(row.querySelector('.fb-field').value);
            e.target.title = OP_HINTS[e.target.value] || e.target.value;
            row.querySelector('.fb-value').outerHTML = valueInputHtml(c2, e.target.value, '');
          }
        }
        var fb = document.getElementById('filter-builder');
        fb?.addEventListener('change', function(e) { onRowChange(e); syncFilters(); });
        fb?.addEventListener('input', function(e) { if (e.target.classList.contains('fb-value')) syncFilters(); });
        fb?.addEventListener('click', function(e) { if (e.target.classList.contains('fb-remove')) { e.target.closest('.fb-row').remove(); syncFilters(); } });
        document.getElementById('add-filter-btn')?.addEventListener('click', function() { addFilterRow(null); syncFilters(); });

        // OR groups delegation: rows behave like top-level rows; plus group controls
        // (the .fbg-match select is not inside a .fb-row, so onRowChange no-ops on it).
        var fg = document.getElementById('filter-groups');
        fg?.addEventListener('change', function(e) { onRowChange(e); syncFilters(); });
        fg?.addEventListener('input', function(e) { if (e.target.classList.contains('fb-value')) syncFilters(); });
        fg?.addEventListener('click', function(e) {
          if (e.target.classList.contains('fb-remove')) { e.target.closest('.fb-row').remove(); syncFilters(); return; }
          var addCond = e.target.closest('.fbg-add-cond');
          if (addCond) { addCond.closest('.fb-group').querySelector('.fbg-rows').appendChild(makeRow(null)); syncFilters(); return; }
          var rmGroup = e.target.closest('.fbg-remove-group');
          if (rmGroup) { rmGroup.closest('.fb-group').remove(); syncFilters(); }
        });
        document.getElementById('add-group-btn')?.addEventListener('click', function() { addGroup(null); syncFilters(); });

        async function loadColumns() {
          var name = getCollectionName();
          var addBtn = document.getElementById('add-filter-btn');
          var addGroupBtn = document.getElementById('add-group-btn');
          if (!name) { viewColumns = []; if (addBtn) addBtn.disabled = true; if (addGroupBtn) addGroupBtn.disabled = true; return; }
          try { var res = await fetch('/admin/views/api/collection-columns/' + encodeURIComponent(name)); var json = await res.json(); viewColumns = (json && json.columns) || []; }
          catch(e) { viewColumns = []; }
          var noCols = viewColumns.length === 0;
          if (addBtn) addBtn.disabled = noCols;
          if (addGroupBtn) addGroupBtn.disabled = noCols;
        }
        function rebuildRowsFromConfig() {
          var rules = [], groups = [];
          try {
            var p = JSON.parse(document.getElementById('view-filter-config').value || '{}');
            if (p && Array.isArray(p.rules)) rules = p.rules;
            if (p && Array.isArray(p.groups)) groups = p.groups;
          } catch(e) {}
          document.getElementById('filter-builder').innerHTML = '';
          rules.forEach(function(r) { addFilterRow(r); });
          document.getElementById('filter-groups').innerHTML = '';
          groups.forEach(function(g) { addGroup(g); });
        }
        async function initFilterBuilder() { await loadColumns(); rebuildRowsFromConfig(); }

        // ── Sort builder (PR-5c) ──────────────────────────────────────
        function sortRowHtml(field, dir) {
          var f = '<select class="sb-field ' + ctl + '">' + viewColumns.map(function(c) { return '<option value="' + esc(c.name) + '"' + (c.name === field ? ' selected' : '') + '>' + esc(c.name) + '</option>'; }).join('') + '</select>';
          var d = '<select class="sb-dir ' + ctl + '"><option value="asc"' + (dir === 'asc' ? ' selected' : '') + '>asc</option><option value="desc"' + (dir !== 'asc' ? ' selected' : '') + '>desc</option></select>';
          return f + d + '<button type="button" class="sb-remove text-zinc-400 hover:text-red-500 px-1.5 text-lg leading-none" title="Remove">&times;</button>';
        }
        function addSortRow(rule) {
          var row = document.createElement('div'); row.className = 'sb-row flex items-center gap-2';
          row.innerHTML = sortRowHtml((rule && rule.field) || (viewColumns[0] && viewColumns[0].name) || '', (rule && rule.direction) || 'asc');
          document.getElementById('sort-builder').appendChild(row);
        }
        function syncSort() {
          var rules = [];
          document.querySelectorAll('#sort-builder .sb-row').forEach(function(row) {
            var f = row.querySelector('.sb-field'); if (!f || !f.value) return;
            rules.push({ field: f.value, direction: row.querySelector('.sb-dir').value });
          });
          document.getElementById('view-sort-config').value = rules.length ? JSON.stringify(rules) : '';
          debouncedPreview();
        }
        function rebuildSortFromConfig() {
          var rules = [];
          try { var p = JSON.parse(document.getElementById('view-sort-config').value || '[]'); if (Array.isArray(p)) rules = p; } catch(e) {}
          document.getElementById('sort-builder').innerHTML = '';
          rules.forEach(function(r) { addSortRow(r); });
        }
        var sbEl = document.getElementById('sort-builder');
        sbEl?.addEventListener('change', syncSort);
        sbEl?.addEventListener('click', function(e) { if (e.target.classList.contains('sb-remove')) { e.target.closest('.sb-row').remove(); syncSort(); } });
        document.getElementById('add-sort-btn')?.addEventListener('click', function() { addSortRow(null); syncSort(); });

        // ── Column picker (PR-5c) ─────────────────────────────────────
        function rebuildColumnsPicker() {
          var selected = {};
          try { var p = JSON.parse(document.getElementById('view-columns-config').value || '{}'); var fields = (p && p.fields) || (Array.isArray(p) ? p : []); fields.forEach(function(f) { selected[f] = 1; }); } catch(e) {}
          var host = document.getElementById('columns-builder'); host.innerHTML = '';
          if (viewColumns.length === 0) { host.innerHTML = '<span class="text-xs text-zinc-400">Pick a collection first.</span>'; return; }
          viewColumns.forEach(function(c) {
            var lbl = document.createElement('label'); lbl.className = 'inline-flex items-center gap-1.5 text-sm text-zinc-700 dark:text-zinc-300';
            lbl.innerHTML = '<input type="checkbox" class="cb-col rounded border-zinc-300 dark:border-zinc-600 text-cyan-600 focus:ring-cyan-500" value="' + esc(c.name) + '"' + (selected[c.name] ? ' checked' : '') + ' /> ' + esc(c.name);
            host.appendChild(lbl);
          });
        }
        function syncColumns() {
          var fields = [];
          document.querySelectorAll('#columns-builder .cb-col:checked').forEach(function(cb) { fields.push(cb.value); });
          document.getElementById('view-columns-config').value = fields.length ? JSON.stringify({ fields: fields }) : '';
          debouncedPreview();
        }
        document.getElementById('columns-builder')?.addEventListener('change', function(e) { if (e.target.classList.contains('cb-col')) syncColumns(); });

        // ── Init all three builders + reset on collection change ──────
        async function initBuilders() {
          await initFilterBuilder();      // loads viewColumns + rebuilds filter rows
          rebuildSortFromConfig();
          rebuildColumnsPicker();
        }
        document.getElementById('view-collection')?.addEventListener('change', async function() {
          await loadColumns();
          ['filter-builder', 'filter-groups', 'sort-builder'].forEach(function(id) { document.getElementById(id).innerHTML = ''; });
          document.getElementById('view-filter-config').value = '';
          document.getElementById('view-sort-config').value = '';
          document.getElementById('view-columns-config').value = '';
          rebuildColumnsPicker();
          previewPage = 1; loadPreview();
        });

        initBuilders();
        loadPreview();

        // Public API for table pagination buttons
        window.__viewsPreview = { goPage: goPage };

      })();
    </script>
  `

  const layoutData: AdminLayoutCatalystData = {
    title: isEdit ? `Edit View: ${data.name}` : 'New View',
    currentPath: '/admin/views',
    user: data.user,
    version: data.version,
    content,
  }

  return renderAdminLayoutCatalyst(layoutData)
}

function formatJson(raw: string | null | undefined): string {
  if (!raw) return ''
  try {
    return JSON.stringify(JSON.parse(raw), null, 2)
  } catch {
    return raw
  }
}
