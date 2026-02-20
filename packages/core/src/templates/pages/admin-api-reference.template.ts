import { renderAdminLayoutCatalyst, AdminLayoutCatalystData } from '../layouts/admin-layout-catalyst.template'
import { CATEGORY_INFO } from '../../services/route-metadata'

export interface APIEndpoint {
  method: string
  path: string
  description: string
  authentication: boolean | 'unknown'
  category: string
  documented?: boolean
}

export interface APIReferencePageData {
  endpoints: APIEndpoint[]
  user?: {
    name: string
    email: string
    role: string
  }
  version?: string
}

function renderAuthBadge(auth: boolean | 'unknown'): string {
  if (auth === true) {
    return `
      <span class="shrink-0 inline-flex items-center gap-x-1 rounded-md bg-amber-50 dark:bg-amber-500/10 px-2 py-1 text-xs font-medium text-amber-700 dark:text-amber-300 ring-1 ring-inset ring-amber-700/10 dark:ring-amber-400/20">
        <svg class="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
        </svg>
        Auth
      </span>`
  }
  if (auth === false) {
    return `
      <span class="shrink-0 inline-flex items-center gap-x-1 rounded-md bg-lime-50 dark:bg-lime-500/10 px-2 py-1 text-xs font-medium text-lime-700 dark:text-lime-300 ring-1 ring-inset ring-lime-700/10 dark:ring-lime-400/20">
        <svg class="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
        </svg>
        Public
      </span>`
  }
  // unknown
  return `
    <span class="shrink-0 inline-flex items-center gap-x-1 rounded-md bg-zinc-50 dark:bg-zinc-500/10 px-2 py-1 text-xs font-medium text-zinc-500 dark:text-zinc-400 ring-1 ring-inset ring-zinc-500/10 dark:ring-zinc-400/20">
      <svg class="h-3 w-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
      </svg>
      Unknown
    </span>`
}

export function renderAPIReferencePage(data: APIReferencePageData): string {
  // Group endpoints by category
  const endpointsByCategory = data.endpoints.reduce((acc, endpoint) => {
    if (!acc[endpoint.category]) {
      acc[endpoint.category] = []
    }
    acc[endpoint.category]!.push(endpoint)
    return acc
  }, {} as Record<string, APIEndpoint[]>)

  // Get unique categories from actual data
  const categories = Object.keys(endpointsByCategory)

  // Count stats
  const totalEndpoints = data.endpoints.length
  const publicEndpoints = data.endpoints.filter(e => e.authentication === false).length
  const protectedEndpoints = data.endpoints.filter(e => e.authentication === true).length
  const undocumentedCount = data.endpoints.filter(e => e.documented === false).length

  const pageContent = `
    <div class="space-y-6">
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">API Reference</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">Auto-discovered documentation of all registered API endpoints</p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16 sm:flex-none">
          <a href="/api" target="_blank" class="inline-flex items-center justify-center gap-x-1.5 rounded-lg bg-zinc-950 dark:bg-white px-3.5 py-2.5 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors shadow-sm">
            <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
            </svg>
            OpenAPI Spec
          </a>
        </div>
      </div>

      <!-- Stats -->
      <dl class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <div class="rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 px-6 py-5">
          <dt class="text-sm/6 font-medium text-zinc-500 dark:text-zinc-400">Total Endpoints</dt>
          <dd class="mt-2 flex items-baseline gap-x-2">
            <span class="text-4xl font-semibold tracking-tight text-zinc-950 dark:text-white">${totalEndpoints}</span>
          </dd>
        </div>
        <div class="rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 px-6 py-5">
          <dt class="text-sm/6 font-medium text-zinc-500 dark:text-zinc-400">Public Endpoints</dt>
          <dd class="mt-2 flex items-baseline gap-x-2">
            <span class="text-4xl font-semibold tracking-tight text-lime-600 dark:text-lime-400">${publicEndpoints}</span>
          </dd>
        </div>
        <div class="rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 px-6 py-5">
          <dt class="text-sm/6 font-medium text-zinc-500 dark:text-zinc-400">Protected Endpoints</dt>
          <dd class="mt-2 flex items-baseline gap-x-2">
            <span class="text-4xl font-semibold tracking-tight text-amber-600 dark:text-amber-400">${protectedEndpoints}</span>
          </dd>
        </div>
        <div class="rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 px-6 py-5">
          <dt class="text-sm/6 font-medium text-zinc-500 dark:text-zinc-400">Categories</dt>
          <dd class="mt-2 flex items-baseline gap-x-2">
            <span class="text-4xl font-semibold tracking-tight text-cyan-600 dark:text-cyan-400">${categories.length}</span>
          </dd>
        </div>
        <div class="rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 px-6 py-5">
          <dt class="text-sm/6 font-medium text-zinc-500 dark:text-zinc-400">Undocumented</dt>
          <dd class="mt-2 flex items-baseline gap-x-2">
            <span class="text-4xl font-semibold tracking-tight ${undocumentedCount > 0 ? 'text-zinc-400 dark:text-zinc-500' : 'text-lime-600 dark:text-lime-400'}">${undocumentedCount}</span>
          </dd>
        </div>
      </dl>

      <!-- Filters -->
      <div class="rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 overflow-hidden">
        <div class="px-6 py-5">
          <div class="flex flex-col sm:flex-row sm:items-end gap-4">
            <div class="flex-1">
              <label class="block text-sm/6 font-medium text-zinc-950 dark:text-white mb-2">Search</label>
              <div class="relative">
                <div class="absolute left-3 top-1/2 -translate-y-1/2">
                  <svg class="h-5 w-5 text-zinc-400 dark:text-zinc-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                  </svg>
                </div>
                <input
                  type="text"
                  id="endpoint-search"
                  placeholder="Search by path or description..."
                  class="w-full rounded-lg bg-white dark:bg-zinc-800 pl-10 pr-3 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow"
                />
              </div>
            </div>
            <div>
              <label class="block text-sm/6 font-medium text-zinc-950 dark:text-white mb-2">Method</label>
              <div class="grid grid-cols-1">
                <select
                  id="method-filter"
                  class="col-start-1 row-start-1 w-full appearance-none rounded-lg bg-white dark:bg-zinc-800 py-2 pl-3 pr-8 text-sm text-zinc-950 dark:text-white outline outline-1 -outline-offset-1 outline-zinc-950/10 dark:outline-white/10 *:bg-white dark:*:bg-zinc-800 focus:outline focus:outline-2 focus:-outline-offset-2 focus:outline-zinc-950 dark:focus:outline-white min-w-[180px]"
                >
                  <option value="">All Methods</option>
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                  <option value="PATCH">PATCH</option>
                  <option value="DELETE">DELETE</option>
                </select>
                <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true" class="pointer-events-none col-start-1 row-start-1 mr-2 size-5 self-center justify-self-end text-zinc-500 dark:text-zinc-400 sm:size-4">
                  <path d="M4.22 6.22a.75.75 0 0 1 1.06 0L8 8.94l2.72-2.72a.75.75 0 1 1 1.06 1.06l-3.25 3.25a.75.75 0 0 1-1.06 0L4.22 7.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" fill-rule="evenodd" />
                </svg>
              </div>
            </div>
            <div>
              <label class="block text-sm/6 font-medium text-zinc-950 dark:text-white mb-2">Category</label>
              <div class="grid grid-cols-1">
                <select
                  id="category-filter"
                  class="col-start-1 row-start-1 w-full appearance-none rounded-lg bg-white dark:bg-zinc-800 py-2 pl-3 pr-8 text-sm text-zinc-950 dark:text-white outline outline-1 -outline-offset-1 outline-zinc-950/10 dark:outline-white/10 *:bg-white dark:*:bg-zinc-800 focus:outline focus:outline-2 focus:-outline-offset-2 focus:outline-zinc-950 dark:focus:outline-white min-w-[200px]"
                >
                  <option value="">All Categories</option>
                  ${categories.map(category => {
                    const info = CATEGORY_INFO[category]
                    const title = info ? info.title : category
                    return `<option value="${category}">${title}</option>`
                  }).join('\n                  ')}
                </select>
                <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true" class="pointer-events-none col-start-1 row-start-1 mr-2 size-5 self-center justify-self-end text-zinc-500 dark:text-zinc-400 sm:size-4">
                  <path d="M4.22 6.22a.75.75 0 0 1 1.06 0L8 8.94l2.72-2.72a.75.75 0 1 1 1.06 1.06l-3.25 3.25a.75.75 0 0 1-1.06 0L4.22 7.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" fill-rule="evenodd" />
                </svg>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- API Categories -->
      <div class="space-y-6">
        ${Object.entries(endpointsByCategory).map(([category, endpoints]) => {
          const info = CATEGORY_INFO[category] || { title: category, description: '', icon: '&#x1f4cb;' }
          return `
            <div class="api-category" data-category="${category}">
              <div class="rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 overflow-hidden">
                <!-- Category Header -->
                <div class="bg-zinc-50 dark:bg-zinc-800/50 px-6 py-4 border-b border-zinc-950/5 dark:border-white/10">
                  <div class="flex items-center">
                    <span class="text-2xl mr-3">${info.icon}</span>
                    <div>
                      <h2 class="text-lg font-semibold text-zinc-950 dark:text-white">${info.title}</h2>
                      <p class="text-sm text-zinc-500 dark:text-zinc-400">${info.description}</p>
                    </div>
                    <div class="ml-auto">
                      <span class="inline-flex items-center rounded-md bg-cyan-50 dark:bg-cyan-500/10 px-2.5 py-1 text-sm font-medium text-cyan-700 dark:text-cyan-300 ring-1 ring-inset ring-cyan-700/10 dark:ring-cyan-400/20">
                        ${endpoints.length} endpoint${endpoints.length !== 1 ? 's' : ''}
                      </span>
                    </div>
                  </div>
                </div>

                <!-- Endpoints List -->
                <div class="divide-y divide-zinc-950/5 dark:divide-white/10">
                  ${endpoints.map(endpoint => `
                    <div class="api-endpoint p-6 hover:bg-zinc-50 dark:hover:bg-zinc-800/50 transition-colors cursor-pointer"
                         data-method="${endpoint.method}"
                         data-path="${endpoint.path}"
                         data-description="${endpoint.description}">
                      <div class="flex items-start gap-x-4">
                        <span class="method-badge method-${endpoint.method.toLowerCase()} shrink-0 px-3 py-1 rounded-md text-xs font-mono font-bold uppercase">
                          ${endpoint.method}
                        </span>
                        <div class="flex-1 min-w-0">
                          <div class="flex items-center gap-x-2 mb-2">
                            <code class="text-zinc-950 dark:text-white text-sm font-mono font-medium break-all">${endpoint.path}</code>
                            ${renderAuthBadge(endpoint.authentication)}
                            ${endpoint.documented === false ? `
                              <span class="shrink-0 inline-flex items-center rounded-md bg-zinc-50 dark:bg-zinc-800 px-2 py-1 text-xs font-medium text-zinc-400 dark:text-zinc-500 ring-1 ring-inset ring-zinc-200 dark:ring-zinc-700">
                                Auto-discovered
                              </span>
                            ` : ''}
                          </div>
                          <p class="text-zinc-600 dark:text-zinc-400 text-sm leading-6">${endpoint.description || '<em class="text-zinc-400 dark:text-zinc-500">No description available</em>'}</p>
                        </div>
                      </div>
                    </div>
                  `).join('')}
                </div>
              </div>
            </div>
          `
        }).join('')}
      </div>

      <!-- No Results Message -->
      <div id="no-results" class="hidden rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-12 text-center">
        <svg class="mx-auto h-12 w-12 text-zinc-400 dark:text-zinc-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
          <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
        <h3 class="mt-4 text-base/7 font-semibold text-zinc-950 dark:text-white">No endpoints found</h3>
        <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">Try adjusting your search or filter criteria</p>
      </div>
    </div>

    <style>
      .method-badge {
        min-width: 60px;
        text-align: center;
      }
      .method-get {
        background-color: rgb(34 197 94);
        color: white;
      }
      .method-post {
        background-color: rgb(59 130 246);
        color: white;
      }
      .method-put {
        background-color: rgb(251 146 60);
        color: white;
      }
      .method-patch {
        background-color: rgb(168 85 247);
        color: white;
      }
      .method-delete {
        background-color: rgb(244 63 94);
        color: white;
      }
    </style>

    <script>
      // Filter functionality
      const searchInput = document.getElementById('endpoint-search');
      const methodFilter = document.getElementById('method-filter');
      const categoryFilter = document.getElementById('category-filter');
      const noResultsDiv = document.getElementById('no-results');

      function filterEndpoints() {
        const searchTerm = searchInput.value.toLowerCase();
        const selectedMethod = methodFilter.value;
        const selectedCategory = categoryFilter.value;

        const categories = document.querySelectorAll('.api-category');
        let visibleEndpoints = 0;

        categories.forEach(category => {
          const categoryName = category.dataset.category;
          const endpoints = category.querySelectorAll('.api-endpoint');
          let visibleInCategory = 0;

          // Check if category should be visible
          const categoryVisible = !selectedCategory || categoryName === selectedCategory;

          if (categoryVisible) {
            endpoints.forEach(endpoint => {
              const method = endpoint.dataset.method;
              const path = endpoint.dataset.path.toLowerCase();
              const description = endpoint.dataset.description.toLowerCase();

              const matchesSearch = !searchTerm ||
                path.includes(searchTerm) ||
                description.includes(searchTerm);
              const matchesMethod = !selectedMethod || method === selectedMethod;

              if (matchesSearch && matchesMethod) {
                endpoint.style.display = 'block';
                visibleInCategory++;
                visibleEndpoints++;
              } else {
                endpoint.style.display = 'none';
              }
            });

            category.style.display = visibleInCategory > 0 ? 'block' : 'none';
          } else {
            category.style.display = 'none';
          }
        });

        // Show/hide no results message
        noResultsDiv.style.display = visibleEndpoints === 0 ? 'block' : 'none';
      }

      // Attach event listeners
      searchInput.addEventListener('input', filterEndpoints);
      methodFilter.addEventListener('change', filterEndpoints);
      categoryFilter.addEventListener('change', filterEndpoints);

      // Copy endpoint path to clipboard
      document.addEventListener('click', function(e) {
        const endpoint = e.target.closest('.api-endpoint');
        if (endpoint && e.target.tagName === 'CODE') {
          const path = endpoint.dataset.path;
          navigator.clipboard.writeText(path).then(() => {
            // Show temporary notification
            const notification = document.createElement('div');
            notification.className = 'fixed top-4 right-4 rounded-lg bg-lime-500 px-4 py-3 shadow-lg ring-1 ring-lime-600/20 z-50';
            notification.innerHTML = '<div class="flex items-center gap-x-2"><svg class="h-5 w-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg><p class="text-sm font-medium text-white">Path copied to clipboard!</p></div>';
            document.body.appendChild(notification);
            setTimeout(() => document.body.removeChild(notification), 2000);
          });
        }
      });
    </script>
  `

  const layoutData: AdminLayoutCatalystData = {
    title: 'API Reference',
    pageTitle: 'API Reference',
    currentPath: '/admin/api-reference',
    user: data.user,
    version: data.version,
    content: pageContent
  }

  return renderAdminLayoutCatalyst(layoutData)
}
