/**
 * API Docs — page renderer (inside the shared admin chrome).
 *
 * Two tabs:
 *   - Endpoints: the auto-discovered catalog from the core route-metadata
 *     service (buildRouteList), grouped by category. All route-derived strings
 *     are escaped (see SECURITY note below).
 *   - Interactive: a Scalar explorer pointed at the plugin's own auth-gated
 *     OpenAPI spec (/admin/plugins/api-docs/openapi.json).
 *
 * SECURITY (N2): route path/description/method/category are rendered ESCAPED
 * via the core `escapeHtml`. Today these come from code-defined route patterns
 * and the maintainer-authored registry, but escaping is unconditional so a
 * route whose metadata ever derives from user/admin data (e.g. collection
 * names) can never inject markup. Category titles/descriptions/icons come from
 * CATEGORY_INFO (trusted, may contain intentional HTML entities) and are left
 * as-is.
 */
import {
  renderAdminLayoutCatalyst,
  type AdminLayoutCatalystData,
} from '../../../../templates/layouts/admin-layout-catalyst.template'
import { CATEGORY_INFO, type RouteMetadata } from '../../../../services'
import { escapeHtml } from '../../../../utils/sanitize'

interface BaseUser {
  name: string
  email: string
  role: string
}

export interface ApiDocsPageData {
  endpoints: RouteMetadata[]
  user?: BaseUser
  version?: string
  dynamicMenuItems?: Array<{ label: string; path: string; icon: string }>
}

const CURRENT_PATH = '/admin/plugins/api-docs'
const SPEC_URL = '/admin/plugins/api-docs/openapi.json'

// Pinned Scalar release + SRI hash (N1). Unpinned `latest` is a supply-chain
// risk; this pins exact bytes. Self-hosting/bundling is the committed follow-up
// (plan F1) — his app sets no CSP, so a CDN script runs unconstrained in the
// admin session; pin+SRI is the interim floor, not the end state.
const SCALAR_VERSION = '1.63.0'
const SCALAR_SRC = `https://cdn.jsdelivr.net/npm/@scalar/api-reference@${SCALAR_VERSION}`
const SCALAR_SRI = 'sha384-bnRzGcRYqM9jbXxeIbNDWWD8mNMY0p8qvmfAyfcT5S7/I6E7bsyLprA0uIP2gUu7'

function renderAuthBadge(auth: boolean | 'unknown'): string {
  if (auth === true) {
    return `<span class="shrink-0 inline-flex items-center gap-x-1 rounded-md bg-amber-50 dark:bg-amber-500/10 px-2 py-1 text-xs font-medium text-amber-700 dark:text-amber-300 ring-1 ring-inset ring-amber-700/10 dark:ring-amber-400/20">Auth</span>`
  }
  if (auth === false) {
    return `<span class="shrink-0 inline-flex items-center gap-x-1 rounded-md bg-lime-50 dark:bg-lime-500/10 px-2 py-1 text-xs font-medium text-lime-700 dark:text-lime-300 ring-1 ring-inset ring-lime-700/10 dark:ring-lime-400/20">Public</span>`
  }
  return `<span class="shrink-0 inline-flex items-center gap-x-1 rounded-md bg-zinc-50 dark:bg-zinc-500/10 px-2 py-1 text-xs font-medium text-zinc-500 dark:text-zinc-400 ring-1 ring-inset ring-zinc-500/10 dark:ring-zinc-400/20">Unknown</span>`
}

function renderEndpointRow(e: RouteMetadata): string {
  const method = escapeHtml(e.method)
  const methodClass = e.method.toLowerCase().replace(/[^a-z]/g, '')
  const path = escapeHtml(e.path)
  // descAttr: plain escaped text for the data-description attribute (read by the
  // client-side search filter). descHtml: same, but with a styled <em> fallback
  // for the visible <p>. Keep them separate — the <em class="…"> fallback's own
  // quotes would break the double-quoted attribute if reused there.
  const descAttr = escapeHtml(e.description)
  const descHtml = e.description
    ? descAttr
    : '<em class="text-zinc-400 dark:text-zinc-500">No description available</em>'
  return `
    <div class="api-endpoint p-6 hover:bg-zinc-50 dark:hover:bg-zinc-800/50 transition-colors"
         data-method="${method}"
         data-path="${path}"
         data-description="${descAttr}">
      <div class="flex items-start gap-x-4">
        <span class="method-badge method-${methodClass} shrink-0 px-3 py-1 rounded-md text-xs font-mono font-bold uppercase">${method}</span>
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-x-2 mb-2">
            <code class="text-zinc-950 dark:text-white text-sm font-mono font-medium break-all">${path}</code>
            ${renderAuthBadge(e.authentication)}
            ${
              e.documented === false
                ? `<span class="shrink-0 inline-flex items-center rounded-md bg-zinc-50 dark:bg-zinc-800 px-2 py-1 text-xs font-medium text-zinc-400 dark:text-zinc-500 ring-1 ring-inset ring-zinc-200 dark:ring-zinc-700">Auto-discovered</span>`
                : ''
            }
          </div>
          <p class="text-zinc-600 dark:text-zinc-400 text-sm leading-6">${descHtml}</p>
        </div>
      </div>
    </div>`
}

export function renderApiDocsPage(data: ApiDocsPageData): string {
  const endpointsByCategory = data.endpoints.reduce((acc, e) => {
    ;(acc[e.category] ??= []).push(e)
    return acc
  }, {} as Record<string, RouteMetadata[]>)
  const categories = Object.keys(endpointsByCategory).sort()

  const total = data.endpoints.length
  const publicCount = data.endpoints.filter((e) => e.authentication === false).length
  const protectedCount = data.endpoints.filter((e) => e.authentication === true).length
  const undocumented = data.endpoints.filter((e) => e.documented === false).length

  const statCard = (label: string, value: number | string, valueClass = 'text-zinc-950 dark:text-white') => `
    <div class="rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 px-6 py-5">
      <dt class="text-sm/6 font-medium text-zinc-500 dark:text-zinc-400">${label}</dt>
      <dd class="mt-2 flex items-baseline gap-x-2"><span class="text-4xl font-semibold tracking-tight ${valueClass}">${value}</span></dd>
    </div>`

  const content = `
    <div class="space-y-6">
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white">API Reference</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">Auto-discovered documentation of all registered API endpoints, generated from the live route table.</p>
        </div>
        <div class="mt-4 sm:mt-0 sm:flex-none">
          <a href="${SPEC_URL}" target="_blank" rel="noopener" class="inline-flex items-center justify-center gap-x-1.5 rounded-lg bg-zinc-950 dark:bg-white px-3.5 py-2.5 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors shadow-sm">OpenAPI Spec</a>
        </div>
      </div>

      <div class="border-b border-zinc-950/10 dark:border-white/10">
        <nav class="-mb-px flex gap-x-6" aria-label="Tabs">
          <button id="tab-endpoints" onclick="apiDocsSwitchTab('endpoints')" class="tab-btn border-b-2 border-zinc-950 dark:border-white px-1 pb-3 text-sm font-semibold text-zinc-950 dark:text-white">Endpoints</button>
          <button id="tab-interactive" onclick="apiDocsSwitchTab('interactive')" class="tab-btn border-b-2 border-transparent px-1 pb-3 text-sm font-medium text-zinc-500 dark:text-zinc-400 hover:border-zinc-300 dark:hover:border-zinc-600 hover:text-zinc-700 dark:hover:text-zinc-300">Interactive</button>
        </nav>
      </div>

      <div id="content-endpoints">
        <dl class="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
          ${statCard('Total Endpoints', total)}
          ${statCard('Public', publicCount, 'text-lime-600 dark:text-lime-400')}
          ${statCard('Protected', protectedCount, 'text-amber-600 dark:text-amber-400')}
          ${statCard('Categories', categories.length, 'text-cyan-600 dark:text-cyan-400')}
          ${statCard('Undocumented', undocumented, undocumented > 0 ? 'text-zinc-400 dark:text-zinc-500' : 'text-lime-600 dark:text-lime-400')}
        </dl>

        <div class="mt-6 rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 px-6 py-5">
          <div class="flex flex-col sm:flex-row sm:items-end gap-4">
            <div class="flex-1">
              <label class="block text-sm/6 font-medium text-zinc-950 dark:text-white mb-2">Search</label>
              <input type="text" id="endpoint-search" placeholder="Search by path or description..." class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow" />
            </div>
            <div>
              <label class="block text-sm/6 font-medium text-zinc-950 dark:text-white mb-2">Category</label>
              <select id="category-filter" class="w-full appearance-none rounded-lg bg-white dark:bg-zinc-800 py-2 pl-3 pr-8 text-sm text-zinc-950 dark:text-white outline outline-1 -outline-offset-1 outline-zinc-950/10 dark:outline-white/10 min-w-[200px]">
                <option value="">All Categories</option>
                ${categories
                  .map((c) => `<option value="${escapeHtml(c)}">${CATEGORY_INFO[c]?.title ?? escapeHtml(c)}</option>`)
                  .join('')}
              </select>
            </div>
          </div>
        </div>

        <div class="mt-6 space-y-6">
          ${categories
            .map((category) => {
              const info = CATEGORY_INFO[category] || { title: escapeHtml(category), description: '', icon: '&#x1f4cb;' }
              const rows = endpointsByCategory[category]!
              return `
              <div class="api-category" data-category="${escapeHtml(category)}">
                <div class="rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 overflow-hidden">
                  <div class="bg-zinc-50 dark:bg-zinc-800/50 px-6 py-4 border-b border-zinc-950/5 dark:border-white/10">
                    <div class="flex items-center">
                      <span class="text-2xl mr-3">${info.icon}</span>
                      <div>
                        <h2 class="text-lg font-semibold text-zinc-950 dark:text-white">${info.title}</h2>
                        <p class="text-sm text-zinc-500 dark:text-zinc-400">${info.description}</p>
                      </div>
                      <div class="ml-auto">
                        <span class="inline-flex items-center rounded-md bg-cyan-50 dark:bg-cyan-500/10 px-2.5 py-1 text-sm font-medium text-cyan-700 dark:text-cyan-300 ring-1 ring-inset ring-cyan-700/10 dark:ring-cyan-400/20">${rows.length} endpoint${rows.length !== 1 ? 's' : ''}</span>
                      </div>
                    </div>
                  </div>
                  <div class="divide-y divide-zinc-950/5 dark:divide-white/10">
                    ${rows.map(renderEndpointRow).join('')}
                  </div>
                </div>
              </div>`
            })
            .join('')}
        </div>

        <div id="no-results" class="hidden mt-6 rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-12 text-center">
          <h3 class="text-base/7 font-semibold text-zinc-950 dark:text-white">No endpoints found</h3>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">Try adjusting your search or filter.</p>
        </div>
      </div>

      <div id="content-interactive" class="hidden">
        <div class="rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 overflow-hidden" style="min-height: 600px;">
          <div id="scalar-loading" class="flex items-center justify-center py-20">
            <p class="text-sm text-zinc-500 dark:text-zinc-400">Loading interactive API explorer…</p>
          </div>
          <div id="scalar-container"></div>
        </div>
      </div>
    </div>

    <style>
      .method-badge { min-width: 60px; text-align: center; }
      .method-get { background-color: rgb(34 197 94); color: white; }
      .method-post { background-color: rgb(59 130 246); color: white; }
      .method-put { background-color: rgb(251 146 60); color: white; }
      .method-patch { background-color: rgb(168 85 247); color: white; }
      .method-delete { background-color: rgb(244 63 94); color: white; }
    </style>

    <script>
      (function () {
        var searchInput = document.getElementById('endpoint-search');
        var categoryFilter = document.getElementById('category-filter');
        var noResults = document.getElementById('no-results');

        function filterEndpoints() {
          var term = (searchInput.value || '').toLowerCase();
          var selectedCategory = categoryFilter.value;
          var cats = document.querySelectorAll('.api-category');
          var visible = 0;
          cats.forEach(function (cat) {
            var catVisible = !selectedCategory || cat.dataset.category === selectedCategory;
            var inCat = 0;
            cat.querySelectorAll('.api-endpoint').forEach(function (ep) {
              var hay = (ep.dataset.path + ' ' + ep.dataset.description).toLowerCase();
              var match = catVisible && (!term || hay.indexOf(term) !== -1);
              ep.style.display = match ? 'block' : 'none';
              if (match) { inCat++; visible++; }
            });
            cat.style.display = (catVisible && inCat > 0) ? 'block' : 'none';
          });
          noResults.style.display = visible === 0 ? 'block' : 'none';
        }
        searchInput.addEventListener('input', filterEndpoints);
        categoryFilter.addEventListener('change', filterEndpoints);

        var scalarLoaded = false;
        window.apiDocsSwitchTab = function (tab) {
          var endpoints = document.getElementById('content-endpoints');
          var interactive = document.getElementById('content-interactive');
          var tabE = document.getElementById('tab-endpoints');
          var tabI = document.getElementById('tab-interactive');
          var active = 'tab-btn border-b-2 border-zinc-950 dark:border-white px-1 pb-3 text-sm font-semibold text-zinc-950 dark:text-white';
          var inactive = 'tab-btn border-b-2 border-transparent px-1 pb-3 text-sm font-medium text-zinc-500 dark:text-zinc-400 hover:border-zinc-300 dark:hover:border-zinc-600 hover:text-zinc-700 dark:hover:text-zinc-300';
          if (tab === 'endpoints') {
            endpoints.classList.remove('hidden'); interactive.classList.add('hidden');
            tabE.className = active; tabI.className = inactive;
          } else {
            endpoints.classList.add('hidden'); interactive.classList.remove('hidden');
            tabE.className = inactive; tabI.className = active;
            if (!scalarLoaded) loadScalar();
          }
        };

        function loadScalar() {
          scalarLoaded = true;
          var container = document.getElementById('scalar-container');
          var loading = document.getElementById('scalar-loading');
          var el = document.createElement('div');
          el.id = 'api-reference';
          el.setAttribute('data-url', ${JSON.stringify(SPEC_URL)});
          el.setAttribute('data-configuration', JSON.stringify({
            theme: 'kepler',
            darkMode: document.documentElement.classList.contains('dark'),
            hideDownloadButton: false,
            hideTestRequestButton: true,
          }));
          container.appendChild(el);
          var script = document.createElement('script');
          script.src = ${JSON.stringify(SCALAR_SRC)};
          script.integrity = ${JSON.stringify(SCALAR_SRI)};
          script.crossOrigin = 'anonymous';
          script.onload = function () { if (loading) loading.style.display = 'none'; };
          script.onerror = function () {
            if (loading) loading.innerHTML = '<div class="text-center py-12"><p class="text-sm text-red-500">Failed to load the interactive explorer (network or integrity check).</p></div>';
          };
          document.head.appendChild(script);
        }
      })();
    </script>
  `

  const layoutData: AdminLayoutCatalystData = {
    title: 'API Reference',
    pageTitle: 'API Reference',
    currentPath: CURRENT_PATH,
    user: data.user,
    content,
    version: data.version,
    dynamicMenuItems: data.dynamicMenuItems,
  }

  return renderAdminLayoutCatalyst(layoutData)
}
