import { renderAdminLayoutCatalyst, type AdminLayoutCatalystData } from '../../../../templates/layouts/admin-layout-catalyst.template'
import { renderTable, type TableColumn } from '../../../../templates/components/table.template'
import { escapeHtml } from '../../../../utils/sanitize'

/** The display kind + its visible-field shape (table columns or cards title+fields). */
export type AdminDisplaySpec =
  | { kind: 'table'; columns: string[] }
  | { kind: 'cards'; titleField: string; fields: string[] }

export interface ViewDisplayPageData {
  view: { id: string; name: string; display_name: string | null }
  display: AdminDisplaySpec
  rows: Record<string, unknown>[]
  meta:
    | { total: number; page: number; pages: number; hasNext: boolean; hasPrev: boolean }
    | { hasNext: boolean; nextCursor: string | null }
  /** The Display-settings picker inputs (#1b). Omit to hide the picker. */
  settings?: { availableColumns: string[]; pageSize: number; paginate: 'offset' | 'cursor' }
  /** Publish state for the publish + share-link panels. `path` is the canonical public slug
   *  (`/v/<path>`) when published. Omit to hide the panels. */
  share?: { isPublic: boolean; shareToken: string | null; path: string | null }
  /** Set when the engine refused (e.g. collection not ready) — rendered as a banner, not a 500. */
  error?: string
  user?: { name: string; email: string; role: string }
  version?: string
}

/** `created_at` → `Created At`. Handles snake_case / kebab-case column keys. */
function humanizeColumn(key: string): string {
  return key.replace(/[_-]+/g, ' ').replace(/\b\w/g, (m) => m.toUpperCase())
}

/** Columns to render: the config whitelist, or every key in the first row when empty=all. */
function effectiveColumns(displayColumns: string[], rows: Record<string, unknown>[]): string[] {
  if (displayColumns.length > 0) return displayColumns
  const first = rows[0]
  return first ? Object.keys(first) : []
}

/**
 * Map the string column list to `TableColumn[]`. The `render` is MANDATORY and
 * non-negotiable: `renderTable` escapes only header labels, NOT body cell values
 * (`table.template.ts`), so rendering raw collection content without this would
 * be a stored-XSS sink (deep-review 🔴 #1).
 */
function toTableColumns(cols: string[]): TableColumn[] {
  return cols.map((key) => ({
    key,
    label: humanizeColumn(key),
    sortable: true,
    sortType: 'string',
    render: (value) => escapeHtml(String(value ?? '')),
  }))
}

/** Render the display body — table (via renderTable) or a card grid. */
function renderAdminDisplayBody(display: AdminDisplaySpec, rows: Record<string, unknown>[]): string {
  if (display.kind === 'table') {
    return renderTable({
      tableId: 'view-display-table',
      columns: toTableColumns(effectiveColumns(display.columns, rows)),
      rows,
      emptyMessage: 'No rows match this view.',
    })
  }
  // cards — read ONLY titleField + fields (never row keys), each value escaped.
  if (!rows.length) {
    return `<div class="rounded-lg border border-dashed border-zinc-300 dark:border-zinc-700 px-6 py-12 text-center text-sm text-zinc-500 dark:text-zinc-400">No rows match this view.</div>`
  }
  const cards = rows
    .map((row) => {
      const heading = `<div class="font-semibold text-zinc-950 dark:text-white mb-2">${escapeHtml(String(row[display.titleField] ?? ''))}</div>`
      const body = display.fields
        .map(
          (f) =>
            `<div class="flex justify-between gap-2 text-sm py-0.5"><span class="text-zinc-500 dark:text-zinc-400">${escapeHtml(humanizeColumn(f))}</span><span class="text-zinc-900 dark:text-zinc-100 text-right break-words">${escapeHtml(String(row[f] ?? ''))}</span></div>`
        )
        .join('')
      return `<div class="rounded-lg border border-zinc-200 dark:border-zinc-700 p-4">${heading}${body}</div>`
    })
    .join('')
  return `<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">${cards}</div>`
}

const linkCls =
  'rounded-md px-3 py-1.5 text-sm font-medium text-zinc-700 dark:text-zinc-200 ring-1 ring-zinc-300 dark:ring-zinc-700 hover:bg-zinc-50 dark:hover:bg-zinc-800'
const disabledCls =
  'rounded-md px-3 py-1.5 text-sm font-medium text-zinc-300 dark:text-zinc-600 ring-1 ring-zinc-200 dark:ring-zinc-800 cursor-not-allowed'

function renderPager(meta: ViewDisplayPageData['meta']): string {
  // Cursor mode: forward-only Next carrying the OPAQUE token, encodeURIComponent'd (base64 +/= would
  // mangle in a query string); a "Newest" reset; no page/total/Prev (keyset has none).
  if (!('page' in meta)) {
    const next =
      meta.hasNext && meta.nextCursor
        ? `<a href="?cursor=${encodeURIComponent(meta.nextCursor)}" class="${linkCls}">Next</a>`
        : `<span class="${disabledCls}">Next</span>`
    return `
    <div class="mt-4 flex items-center justify-end gap-x-2">
      <a href="?" class="${linkCls}">Newest</a> ${next}
    </div>
  `
  }
  const prev = meta.hasPrev ? `<a href="?page=${meta.page - 1}" class="${linkCls}">Previous</a>` : `<span class="${disabledCls}">Previous</span>`
  const next = meta.hasNext ? `<a href="?page=${meta.page + 1}" class="${linkCls}">Next</a>` : `<span class="${disabledCls}">Next</span>`
  return `
    <div class="mt-4 flex items-center justify-between">
      <span class="text-sm text-zinc-500 dark:text-zinc-400">
        Page ${meta.page} of ${meta.pages} &middot; ${meta.total} result${meta.total !== 1 ? 's' : ''}
      </span>
      <div class="flex gap-x-2">${prev} ${next}</div>
    </div>
  `
}

/** A JSON value safe to embed inside a `<script>` tag (neutralize `</script>`). */
function jsonForScript(value: unknown): string {
  return JSON.stringify(value).replace(/</g, '\\u003c')
}

/**
 * The Display-settings picker (#1b): choose table vs cards + the visible fields,
 * then PUT to /:id/display/config. Collection column names are escapeHtml'd into
 * markup and JSON-encoded into the inline script; the script is self-contained and
 * re-attaches on each full render (no event delegation needed — it runs once).
 */
/**
 * Publish/unpublish an embed. Not-public → a slug input + Publish (POST /:id/display/publish);
 * public → the canonical /v/<path> link + Unpublish (POST /:id/display/unpublish). Errors from
 * the route (e.g. "set the display config first", duplicate slug) render inline. Reloads on
 * success so the panels re-render for the new state.
 */
function renderPublishPanel(
  viewId: string,
  viewName: string,
  share: { isPublic: boolean; path: string | null } | undefined,
): string {
  const isPublic = share?.isPublic ?? false
  const idJs = jsonForScript(viewId)
  if (isPublic) {
    const url = escapeHtml(`/v/${share?.path ?? ''}`)
    return `
    <div class="mb-6 rounded-lg border border-emerald-300 dark:border-emerald-700/50 bg-emerald-50 dark:bg-emerald-900/20 px-4 py-3">
      <div class="flex items-center justify-between gap-3">
        <div>
          <span class="block text-xs font-medium text-emerald-700 dark:text-emerald-300 mb-1">Public embed — live</span>
          <a href="${url}" target="_blank" class="text-sm font-mono text-emerald-800 dark:text-emerald-200 hover:underline">${url}</a>
        </div>
        <button type="button" id="view-unpublish" class="rounded-md px-3 py-2 text-sm font-semibold text-red-700 dark:text-red-300 ring-1 ring-inset ring-red-300 dark:ring-red-700 hover:bg-red-50 dark:hover:bg-red-900/30">Unpublish</button>
      </div>
      <div id="publish-msg" class="mt-2 text-sm text-red-600 dark:text-red-400 hidden"></div>
    </div>
    <script>
      (function() {
        var b = document.getElementById('view-unpublish'); if (!b) return;
        b.addEventListener('click', async function() {
          if (!confirm('Unpublish this public embed? The /v/ link stops working.')) return;
          b.disabled = true;
          var res = await fetch('/admin/views/' + encodeURIComponent(${idJs}) + '/display/unpublish', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
          if (res.ok) { location.reload(); return; }
          var m = document.getElementById('publish-msg');
          m.textContent = (await res.json().catch(function(){return{}})).error || 'Unpublish failed';
          m.classList.remove('hidden'); b.disabled = false;
        });
      })();
    </script>`
  }
  return `
    <div class="mb-6 rounded-lg border border-zinc-200 dark:border-zinc-700 px-4 py-3">
      <label class="block text-xs font-medium text-zinc-500 dark:text-zinc-400 mb-1">Publish a public embed</label>
      <p class="text-xs text-zinc-500 dark:text-zinc-400 mb-2">Serves this display's published rows at a public URL with no admin chrome. Set the display columns above first.</p>
      <div class="flex items-center gap-2">
        <span class="text-sm text-zinc-400 dark:text-zinc-500 font-mono">/v/</span>
        <input id="publish-path" type="text" value="${escapeHtml(viewName)}" placeholder="path" pattern="[a-z0-9][a-z0-9_-]*"
          class="flex-1 rounded-md border border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-mono text-zinc-900 dark:text-zinc-100">
        <button type="button" id="view-publish" class="rounded-md px-3 py-2 text-sm font-semibold text-cyan-700 dark:text-cyan-300 ring-1 ring-inset ring-cyan-300 dark:ring-cyan-700 hover:bg-cyan-50 dark:hover:bg-cyan-900/30">Publish</button>
      </div>
      <div id="publish-msg" class="mt-2 text-sm text-red-600 dark:text-red-400 hidden"></div>
    </div>
    <script>
      (function() {
        var b = document.getElementById('view-publish'); if (!b) return;
        b.addEventListener('click', async function() {
          var path = (document.getElementById('publish-path').value || '').trim();
          var m = document.getElementById('publish-msg'); m.classList.add('hidden');
          b.disabled = true;
          var res = await fetch('/admin/views/' + encodeURIComponent(${idJs}) + '/display/publish', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path: path }) });
          if (res.ok) { location.reload(); return; }
          m.textContent = (await res.json().catch(function(){return{}})).error || 'Publish failed';
          m.classList.remove('hidden'); b.disabled = false;
        });
      })();
    </script>`
}

/** The public share-link panel (the unlisted `/v/<token>` link + copy). */
function renderShareLink(share: { isPublic: boolean; shareToken: string | null }): string {
  if (!share.isPublic) return ''
  if (!share.shareToken) {
    return `<div class="mb-6 rounded-lg border border-zinc-200 dark:border-zinc-700 px-4 py-3 text-sm text-zinc-500 dark:text-zinc-400">Re-publish this display to mint a shareable link.</div>`
  }
  const url = escapeHtml(`/v/${share.shareToken}`)
  return `
    <div class="mb-6 rounded-lg border border-zinc-200 dark:border-zinc-700 px-4 py-3">
      <label class="block text-xs font-medium text-zinc-500 dark:text-zinc-400 mb-1">Public share link</label>
      <div class="flex items-center gap-2">
        <input id="share-link" type="text" readonly value="${url}" class="flex-1 rounded-md border border-zinc-300 dark:border-zinc-600 bg-zinc-50 dark:bg-zinc-800 px-3 py-2 text-sm font-mono text-zinc-700 dark:text-zinc-200">
        <button type="button" id="share-copy" class="rounded-md px-3 py-2 text-sm font-semibold text-cyan-700 dark:text-cyan-300 ring-1 ring-inset ring-cyan-300 dark:ring-cyan-700 hover:bg-cyan-50 dark:hover:bg-cyan-900/30">Copy</button>
      </div>
    </div>
    <script>
    (function(){
      var btn = document.getElementById('share-copy');
      if(!btn) return;
      btn.addEventListener('click', function(){
        var input = document.getElementById('share-link');
        input.select();
        try { navigator.clipboard.writeText(input.value); btn.textContent = 'Copied'; setTimeout(function(){ btn.textContent = 'Copy'; }, 1500); } catch(e){ document.execCommand('copy'); }
      });
    })();
    </script>
  `
}

function renderDisplaySettings(
  view: ViewDisplayPageData['view'],
  display: AdminDisplaySpec,
  settings: { availableColumns: string[]; pageSize: number; paginate: 'offset' | 'cursor' }
): string {
  const cols = settings.availableColumns
  const checkboxes = (cls: string) =>
    cols
      .map(
        (c) =>
          `<label class="flex items-center gap-2 text-sm py-0.5"><input type="checkbox" class="${cls}" value="${escapeHtml(c)}"> ${escapeHtml(humanizeColumn(c))}</label>`
      )
      .join('')
  const titleOptions = cols
    .map((c) => `<option value="${escapeHtml(c)}">${escapeHtml(humanizeColumn(c))}</option>`)
    .join('')
  const current =
    display.kind === 'table'
      ? { type: 'table', columns: display.columns }
      : { type: 'cards', titleField: display.titleField, fields: display.fields }
  const inputCls =
    'mt-1 block w-full rounded-md border border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 px-3 py-2 text-sm'

  return `
    <details class="mb-6 rounded-lg border border-zinc-200 dark:border-zinc-700">
      <summary class="cursor-pointer px-4 py-3 text-sm font-semibold text-zinc-700 dark:text-zinc-200">Display settings</summary>
      <div class="px-4 py-4 border-t border-zinc-200 dark:border-zinc-700 space-y-4">
        <div>
          <label class="block text-xs font-medium text-zinc-500 dark:text-zinc-400">Type</label>
          <select id="ds-type" class="${inputCls}"><option value="table">Table</option><option value="cards">Cards</option></select>
        </div>
        <div id="ds-table-section">
          <label class="block text-xs font-medium text-zinc-500 dark:text-zinc-400 mb-1">Columns</label>
          <div id="ds-columns" class="grid grid-cols-2 gap-x-4">${checkboxes('ds-col')}</div>
        </div>
        <div id="ds-cards-section" class="hidden space-y-3">
          <div>
            <label class="block text-xs font-medium text-zinc-500 dark:text-zinc-400">Title field</label>
            <select id="ds-title" class="${inputCls}">${titleOptions}</select>
          </div>
          <div>
            <label class="block text-xs font-medium text-zinc-500 dark:text-zinc-400 mb-1">Body fields</label>
            <div id="ds-fields" class="grid grid-cols-2 gap-x-4">${checkboxes('ds-field')}</div>
          </div>
        </div>
        <div>
          <label class="block text-xs font-medium text-zinc-500 dark:text-zinc-400">Page size</label>
          <input type="number" id="ds-pagesize" min="1" max="100" value="${settings.pageSize}" class="${inputCls}">
        </div>
        <div>
          <label class="block text-xs font-medium text-zinc-500 dark:text-zinc-400">Pagination</label>
          <select id="ds-paginate" class="${inputCls}">
            <option value="offset"${settings.paginate === 'offset' ? ' selected' : ''}>Page numbers (offset)</option>
            <option value="cursor"${settings.paginate === 'cursor' ? ' selected' : ''}>Cursor / infinite scroll (keyset — requires a sort by updated_at, created_at, or id)</option>
          </select>
        </div>
        <div class="flex items-center gap-3">
          <button type="button" id="ds-save" class="inline-flex items-center rounded-md bg-cyan-600 px-3 py-2 text-sm font-semibold text-white hover:bg-cyan-500">Save display</button>
          <span id="ds-msg" class="text-xs text-zinc-500"></span>
        </div>
      </div>
    </details>
    <script>
    (function(){
      var viewId = ${jsonForScript(view.id)};
      var current = ${jsonForScript(current)};
      var typeSel = document.getElementById('ds-type');
      var tableSec = document.getElementById('ds-table-section');
      var cardsSec = document.getElementById('ds-cards-section');
      function esc(c){ return (window.CSS && CSS.escape) ? CSS.escape(c) : c.replace(/["\\\\]/g,'\\\\$&'); }
      function sync(){ var t = typeSel.value; tableSec.classList.toggle('hidden', t!=='table'); cardsSec.classList.toggle('hidden', t!=='cards'); }
      typeSel.value = current.type;
      (current.columns||[]).forEach(function(c){ var el = document.querySelector('.ds-col[value="'+esc(c)+'"]'); if(el) el.checked = true; });
      if(current.titleField){ var ts = document.getElementById('ds-title'); if(ts) ts.value = current.titleField; }
      (current.fields||[]).forEach(function(c){ var el = document.querySelector('.ds-field[value="'+esc(c)+'"]'); if(el) el.checked = true; });
      sync();
      typeSel.addEventListener('change', sync);
      document.getElementById('ds-save').addEventListener('click', async function(){
        var type = typeSel.value;
        var pageSize = Math.max(1, Math.min(100, parseInt(document.getElementById('ds-pagesize').value,10)||25));
        var paginate = document.getElementById('ds-paginate').value === 'cursor' ? 'cursor' : 'offset';
        var config;
        if(type==='table'){
          var columns = Array.prototype.slice.call(document.querySelectorAll('.ds-col:checked')).map(function(e){return e.value;});
          config = { type:'table', version:1, columns: columns, pageSize: pageSize, paginate: paginate };
        } else {
          var titleField = document.getElementById('ds-title').value;
          var fields = Array.prototype.slice.call(document.querySelectorAll('.ds-field:checked')).map(function(e){return e.value;});
          config = { type:'cards', version:1, titleField: titleField, fields: fields, pageSize: pageSize, paginate: paginate };
        }
        var msg = document.getElementById('ds-msg');
        msg.textContent = 'Saving…'; msg.className = 'text-xs text-zinc-500';
        try {
          var res = await fetch('/admin/views/'+encodeURIComponent(viewId)+'/display/config', { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ display_type: type, config: config }) });
          if(res.ok){ location.reload(); return; }
          var j = await res.json().catch(function(){return {};});
          msg.textContent = (j && j.error) ? j.error : 'Save failed'; msg.className = 'text-xs text-red-600';
        } catch(e){ msg.textContent = 'Save failed'; msg.className = 'text-xs text-red-600'; }
      });
    })();
    </script>
  `
}

export function renderViewDisplayPage(data: ViewDisplayPageData): string {
  const titleName = escapeHtml(data.view.display_name || data.view.name)

  const body = data.error
    ? `
      <div class="rounded-lg border border-amber-300 dark:border-amber-700/50 bg-amber-50 dark:bg-amber-900/20 px-6 py-8 text-center">
        <p class="text-sm font-medium text-amber-800 dark:text-amber-300">${escapeHtml(data.error)}</p>
      </div>
    `
    : `
      ${renderAdminDisplayBody(data.display, data.rows)}
      ${renderPager(data.meta)}
    `

  const content = `
    <div class="mx-auto max-w-7xl">
      <div class="sm:flex sm:items-center sm:justify-between mb-8">
        <div>
          <a href="/admin/views" class="text-sm text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200">&larr; Views</a>
          <h1 class="mt-2 text-2xl font-bold text-zinc-950 dark:text-white">
            ${titleName}
            <span class="ml-2 text-sm text-zinc-400 dark:text-zinc-500 font-mono">${escapeHtml(data.view.name)}</span>
          </h1>
        </div>
        <div class="mt-4 sm:mt-0 flex gap-x-2">
          <a href="/admin/views/${encodeURIComponent(data.view.id)}"
             class="inline-flex items-center rounded-md px-3 py-2 text-sm font-semibold text-zinc-700 dark:text-zinc-200 ring-1 ring-inset ring-zinc-300 dark:ring-zinc-700 hover:bg-zinc-50 dark:hover:bg-zinc-800">
            Edit
          </a>
          <a href="/api/views/${encodeURIComponent(data.view.name)}" target="_blank"
             class="inline-flex items-center rounded-md px-3 py-2 text-sm font-semibold text-cyan-700 dark:text-cyan-300 ring-1 ring-inset ring-cyan-300 dark:ring-cyan-700 hover:bg-cyan-50 dark:hover:bg-cyan-900/30">
            API
          </a>
        </div>
      </div>
      ${data.settings && data.settings.availableColumns.length > 0 ? renderDisplaySettings(data.view, data.display, data.settings) : ''}
      ${data.share ? renderPublishPanel(data.view.id, data.view.name, data.share) : ''}
      ${data.share ? renderShareLink(data.share) : ''}
      ${body}
    </div>
  `

  const layoutData: AdminLayoutCatalystData = {
    title: `${data.view.display_name || data.view.name} — Display`,
    currentPath: '/admin/views',
    user: data.user,
    version: data.version,
    content,
  }
  return renderAdminLayoutCatalyst(layoutData)
}
