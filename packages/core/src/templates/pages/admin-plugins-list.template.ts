import {
  getConfirmationDialogScript,
  renderConfirmationDialog,
} from '../components/confirmation-dialog.template';
import {
  AdminLayoutCatalystData,
  renderAdminLayoutCatalyst,
} from '../layouts/admin-layout-catalyst.template';

export interface Plugin {
  id: string;
  name: string;
  displayName: string;
  description: string;
  version: string;
  author: string;
  status: 'active' | 'inactive' | 'error' | 'uninstalled';
  category: string;
  icon: string;
  downloadCount?: number;
  rating?: number;
  lastUpdated: string;
  dependencies?: string[];
  permissions?: string[];
  isCore?: boolean;
}

export interface PluginsListPageData {
  plugins: Plugin[];
  stats?: {
    total: number;
    active: number;
    inactive: number;
    errors: number;
    uninstalled: number;
  };
  user?: {
    name: string;
    email: string;
    role: string;
  };
  version?: string;
}

export function renderPluginsListPage(data: PluginsListPageData): string {
  const categories = [
    { value: 'content', label: 'Content Management' },
    { value: 'media', label: 'Media' },
    { value: 'editor', label: 'Editors' },
    { value: 'seo', label: 'SEO & Analytics' },
    { value: 'security', label: 'Security' },
    { value: 'utilities', label: 'Utilities' },
    { value: 'system', label: 'System' },
    { value: 'development', label: 'Development' },
    { value: 'demo', label: 'Demo' },
  ];

  const statuses = [
    { value: 'active', label: 'Active' },
    { value: 'inactive', label: 'Inactive' },
    { value: 'uninstalled', label: 'Available to Install' },
    { value: 'error', label: 'Error' },
  ];

  // Calculate counts
  const categoryCounts: Record<string, number> = {};
  categories.forEach((cat) => {
    categoryCounts[cat.value] = data.plugins.filter((p) => p.category === cat.value).length;
  });

  // Sort categories by count (descending)
  categories.sort((a, b) => (categoryCounts[b.value] || 0) - (categoryCounts[a.value] || 0));

  const statusCounts: Record<string, number> = {};
  statuses.forEach((status) => {
    statusCounts[status.value] = data.plugins.filter((p) => p.status === status.value).length;
  });

  // Sort statuses by count (descending)
  statuses.sort((a, b) => (statusCounts[b.value] || 0) - (statusCounts[a.value] || 0));

  const pageContent = `
    <div>
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-8">
        <div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">Plugins</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">Manage and extend functionality with plugins</p>
        </div>
      </div>

      <!-- Experimental Notice -->
      <div class="mb-8 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800/50 p-4">
        <div class="flex items-start">
          <div class="flex-shrink-0">
            <svg class="h-5 w-5 text-amber-600 dark:text-amber-400" viewBox="0 0 20 20" fill="currentColor">
              <path fill-rule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 5a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 5zm0 9a1 1 0 100-2 1 1 0 000 2z" clip-rule="evenodd" />
            </svg>
          </div>
        </div>
      </div>

      <div class="flex flex-col lg:flex-row gap-8">
        <!-- Sidebar Filters -->
        <aside class="w-full lg:w-48 flex-shrink-0 space-y-8 lg:sticky lg:top-6 lg:self-start">
          <!-- Categories Filter -->
          <div>
            <h3 class="text-sm font-semibold text-zinc-950 dark:text-white mb-4">Categories</h3>
            <div class="space-y-3">
              ${categories
                .map((cat) => {
                  const count = categoryCounts[cat.value] || 0;
                  const isDisabled = count === 0;
                  return `
                <div class="flex items-center ${isDisabled ? 'opacity-50' : ''}">
                  <input
                    id="category-${cat.value}"
                    name="category"
                    value="${cat.value}"
                    type="checkbox"
                    onchange="filterAndSortPlugins()"
                    class="h-4 w-4 rounded border-zinc-300 dark:border-zinc-700 text-zinc-900 focus:ring-zinc-600 dark:bg-zinc-900 disabled:cursor-not-allowed"
                    ${isDisabled ? 'disabled' : ''}
                  >
                  <label for="category-${cat.value}" class="ml-3 text-sm text-zinc-600 dark:text-zinc-400 select-none ${isDisabled ? 'cursor-not-allowed' : ''}">
                    ${cat.label} <span class="text-zinc-400 dark:text-zinc-500">(${count})</span>
                  </label>
                </div>
              `;
                })
                .join('')}
            </div>
          </div>

          <div class="h-px bg-zinc-200 dark:bg-zinc-800 lg:hidden"></div>

          <!-- Status Filter -->
          <div>
            <h3 class="text-sm font-semibold text-zinc-950 dark:text-white mb-4">Status</h3>
            <div class="space-y-3">
              ${statuses
                .map((status) => {
                  const count = statusCounts[status.value] || 0;
                  const isDisabled = count === 0;
                  let colorClass = '';
                  let ringClass = '';
                  let dotClass = '';

                  switch (status.value) {
                    case 'active':
                      colorClass =
                        'text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-500/10';
                      ringClass = 'ring-emerald-600/20';
                      dotClass = 'bg-emerald-500 dark:bg-emerald-400';
                      break;
                    case 'inactive':
                      colorClass =
                        'text-zinc-700 dark:text-zinc-400 bg-zinc-50 dark:bg-zinc-500/10';
                      ringClass = 'ring-zinc-600/20';
                      dotClass = 'bg-zinc-500 dark:bg-zinc-400';
                      break;
                    case 'error':
                      colorClass = 'text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-500/10';
                      ringClass = 'ring-red-600/20';
                      dotClass = 'bg-red-500 dark:bg-red-400';
                      break;
                    case 'uninstalled':
                      colorClass =
                        'text-yellow-700 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-500/10';
                      ringClass = 'ring-yellow-600/20';
                      dotClass = 'bg-yellow-500 dark:bg-yellow-400';
                      break;
                    default:
                      colorClass =
                        'text-zinc-700 dark:text-zinc-400 bg-zinc-50 dark:bg-zinc-500/10';
                      ringClass = 'ring-zinc-600/20';
                      dotClass = 'bg-zinc-500 dark:bg-zinc-400';
                  }

                  return `
                <div class="flex items-center ${isDisabled ? 'opacity-50' : ''}">
                  <input
                    id="status-${status.value}"
                    name="status"
                    value="${status.value}"
                    type="checkbox"
                    onchange="filterAndSortPlugins()"
                    class="h-4 w-4 rounded border-zinc-300 dark:border-zinc-700 text-zinc-900 focus:ring-zinc-600 dark:bg-zinc-900 disabled:cursor-not-allowed"
                    ${isDisabled ? 'disabled' : ''}
                  >
                  <label for="status-${status.value}" class="ml-3 cursor-pointer select-none flex items-center ${isDisabled ? 'cursor-not-allowed' : ''}">
                    <span class="inline-flex items-center rounded-md px-2 py-1 text-xs font-medium ring-1 ring-inset ${colorClass} ${ringClass}">
                      <span class="mr-1.5 h-1.5 w-1.5 rounded-full ${dotClass}"></span>
                      ${status.label}
                    </span>
                    <span class="ml-2 text-xs text-zinc-500 dark:text-zinc-400">(${count})</span>
                  </label>
                </div>
              `;
                })
                .join('')}
            </div>
          </div>
        </aside>

        <!-- Main Content -->
        <div class="flex-1 min-w-0">
          <!-- Stats Row (Compact) -->
          <div class="flex flex-wrap gap-4 mb-6">
            <div class="min-w-[140px] rounded-lg bg-zinc-50 dark:bg-zinc-800/50 p-3 ring-1 ring-inset ring-zinc-950/5 dark:ring-white/5">
              <div class="text-xs font-medium text-zinc-500 dark:text-zinc-400">Total</div>
              <div class="mt-1 text-lg font-semibold text-zinc-900 dark:text-white">${data.stats?.total || 0}</div>
            </div>
            <div class="min-w-[140px] rounded-lg bg-zinc-50 dark:bg-zinc-800/50 p-3 ring-1 ring-inset ring-zinc-950/5 dark:ring-white/5">
              <div class="text-xs font-medium text-zinc-500 dark:text-zinc-400">Active</div>
              <div class="mt-1 text-lg font-semibold text-emerald-600 dark:text-emerald-400">${data.stats?.active || 0}</div>
            </div>
            <div class="min-w-[140px] rounded-lg bg-zinc-50 dark:bg-zinc-800/50 p-3 ring-1 ring-inset ring-zinc-950/5 dark:ring-white/5">
              <div class="text-xs font-medium text-zinc-500 dark:text-zinc-400">Available</div>
              <div class="mt-1 text-lg font-semibold text-zinc-600 dark:text-zinc-400">${data.stats?.uninstalled || 0}</div>
            </div>
            <div class="min-w-[140px] rounded-lg bg-zinc-50 dark:bg-zinc-800/50 p-3 ring-1 ring-inset ring-zinc-950/5 dark:ring-white/5">
              <div class="text-xs font-medium text-zinc-500 dark:text-zinc-400">Errors</div>
              <div class="mt-1 text-lg font-semibold text-red-600 dark:text-red-400">${data.stats?.errors || 0}</div>
            </div>
          </div>

          <!-- Toolbar -->
          <div class="flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between mb-6">
            <div class="relative flex-1 w-full">
              <div class="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3">
                <svg class="h-4 w-4 text-zinc-400" viewBox="0 0 20 20" fill="currentColor">
                  <path fill-rule="evenodd" d="M9 3.5a5.5 5.5 0 100 11 5.5 5.5 0 000-11zM2 9a7 7 0 1112.452 4.391l3.328 3.329a.75.75 0 11-1.06 1.06l-3.329-3.328A7 7 0 012 9z" clip-rule="evenodd" />
                </svg>
              </div>
              <input
                id="search-input"
                type="text"
                placeholder="Search plugins..."
                oninput="filterAndSortPlugins()"
                class="block w-full h-9 rounded-md border-0 py-1.5 pl-10 text-zinc-900 ring-1 ring-inset ring-zinc-300 placeholder:text-zinc-400 focus:ring-2 focus:ring-inset focus:ring-zinc-600 dark:bg-zinc-900 dark:text-white dark:ring-zinc-700 dark:focus:ring-zinc-500 sm:text-sm sm:leading-6"
              >
            </div>

            <div class="flex items-center gap-3 w-full sm:w-auto">
              <select id="sort-filter" onchange="filterAndSortPlugins()" class="block w-full sm:w-auto h-9 rounded-md border-0 py-1.5 pl-3 pr-8 text-zinc-900 ring-1 ring-inset ring-zinc-300 focus:ring-2 focus:ring-inset focus:ring-zinc-600 dark:bg-zinc-900 dark:text-white dark:ring-zinc-700 dark:focus:ring-zinc-500 sm:text-sm sm:leading-6">
                <option value="name-asc">Name (A-Z)</option>
                <option value="name-desc">Name (Z-A)</option>
                <option value="newest">Newest Installed</option>
                <option value="updated">Recently Updated</option>
                <option value="popular">Popularity</option>
                <option value="rating">Highest Rated</option>
              </select>

              <button
                onclick="location.reload()"
                class="inline-flex items-center gap-x-1.5 rounded-md bg-white dark:bg-zinc-900 px-3 py-1.5 h-9 text-sm font-semibold text-zinc-900 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-300 dark:ring-zinc-700 hover:bg-zinc-50 dark:hover:bg-zinc-800"
              >
                <svg class="h-4 w-4 text-zinc-500 dark:text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                </svg>
              </button>
            </div>
          </div>

          <!-- Plugins Grid -->
          <div id="plugins-grid" class="grid gap-6" style="grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));">
            ${data.plugins.map((plugin) => renderPluginCard(plugin)).join('')}
          </div>
        </div>
      </div>
    </div>

    <script>
      async function togglePlugin(pluginId, action, event) {
        const button = event.target.closest('button');
        if (!button) return;

        button.disabled = true;
        button.classList.add('opacity-50', 'cursor-wait');
        
        try {
          const response = await fetch(\`/admin/plugins/\${pluginId}/\${action}\`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            }
          });
          
          const result = await response.json();
          
          if (result.success) {
            // Update UI
            const card = button.closest('.plugin-card');
            const statusBadge = card.querySelector('.status-badge');
            const knob = button.querySelector('.toggle-knob');

            if (action === 'activate') {
              // Update status badge
              statusBadge.className = 'status-badge inline-flex items-center rounded-full px-1.5 py-0.5 text-[10px] font-medium ring-1 ring-inset bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 ring-emerald-600/20';
              statusBadge.innerHTML = '<div class="w-1.5 h-1.5 bg-emerald-500 dark:bg-emerald-400 rounded-full mr-1.5"></div>Active';
              
              // Update button state to Active
              button.className = 'bg-emerald-600 relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-emerald-600 focus:ring-offset-2 toggle-button';
              button.setAttribute('aria-checked', 'true');
              button.onclick = (event) => togglePlugin(pluginId, 'deactivate', event);
              
              // Update knob position
              if (knob) {
                knob.className = 'translate-x-5 pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out toggle-knob';
              }
            } else {
              // Update status badge
              statusBadge.className = 'status-badge inline-flex items-center rounded-full px-1.5 py-0.5 text-[10px] font-medium ring-1 ring-inset bg-zinc-50 dark:bg-zinc-500/10 text-zinc-700 dark:text-zinc-400 ring-zinc-600/20';
              statusBadge.innerHTML = '<div class="w-1.5 h-1.5 bg-zinc-500 dark:bg-zinc-400 rounded-full mr-1.5"></div>Inactive';
              
              // Update button state to Inactive
              button.className = 'bg-zinc-200 dark:bg-zinc-700 relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-emerald-600 focus:ring-offset-2 toggle-button';
              button.setAttribute('aria-checked', 'false');
              button.onclick = (event) => togglePlugin(pluginId, 'activate', event);
              
              // Update knob position
              if (knob) {
                knob.className = 'translate-x-0 pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out toggle-knob';
              }
            }

            showNotification(\`Plugin \${action}d successfully\`, 'success');
          } else {
            throw new Error(result.error || \`Failed to \${action} plugin\`);
          }
        } catch (error) {
          showNotification(error.message, 'error');
        } finally {
          button.disabled = false;
          button.classList.remove('opacity-50', 'cursor-wait');
        }
      }
      
      async function installPlugin(pluginName) {
        const button = event.target;
        button.disabled = true;
        button.textContent = 'Installing...';
        
        try {
          const response = await fetch('/admin/plugins/install', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ name: pluginName })
          });
          
          const result = await response.json();
          
          if (result.success) {
            showNotification('Plugin installed successfully!', 'success');
            setTimeout(() => location.reload(), 1500);
          } else {
            throw new Error(result.error || 'Failed to install plugin');
          }
        } catch (error) {
          showNotification(error.message, 'error');
          button.disabled = false;
          button.textContent = 'Install';
        }
      }
      
      let pluginToUninstall = null;

      async function uninstallPlugin(pluginId) {
        pluginToUninstall = pluginId;
        showConfirmDialog('uninstall-plugin-confirm');
      }

      async function performUninstallPlugin() {
        if (!pluginToUninstall) return;

        const button = event.target;
        if (button) button.disabled = true;

        try {
          const response = await fetch(\`/admin/plugins/\${pluginToUninstall}/uninstall\`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            }
          });

          const result = await response.json();

          if (result.success) {
            showNotification('Plugin uninstalled successfully!', 'success');
            setTimeout(() => location.reload(), 1500);
          } else {
            throw new Error(result.error || 'Failed to uninstall plugin');
          }
        } catch (error) {
          showNotification(error.message, 'error');
          if (button) button.disabled = false;
        } finally {
          pluginToUninstall = null;
        }
      }
      
      function openPluginSettings(pluginId) {
        window.location.href = \`/admin/plugins/\${pluginId}\`;
      }
      
      function filterAndSortPlugins() {
        // Get checked categories
        const checkedCategories = Array.from(document.querySelectorAll('input[name="category"]:checked'))
          .map(cb => cb.value.toLowerCase());
          
        // Get checked statuses
        const checkedStatuses = Array.from(document.querySelectorAll('input[name="status"]:checked'))
          .map(cb => cb.value.toLowerCase());
          
        const searchInput = document.getElementById('search-input').value.toLowerCase();
        const sortValue = document.getElementById('sort-filter').value;

        const pluginsGrid = document.getElementById('plugins-grid');
        const pluginCards = Array.from(pluginsGrid.querySelectorAll('.plugin-card'));
        
        // Filter
        const visibleCards = pluginCards.filter(card => {
          const category = card.getAttribute('data-category')?.toLowerCase() || '';
          const status = card.getAttribute('data-status')?.toLowerCase() || '';
          const name = card.getAttribute('data-name')?.toLowerCase() || '';
          const description = card.getAttribute('data-description')?.toLowerCase() || '';

          // Category filter: if any selected, must match one of them
          if (checkedCategories.length > 0 && !checkedCategories.includes(category)) return false;
          
          // Status filter: if any selected, must match one of them
          if (checkedStatuses.length > 0 && !checkedStatuses.includes(status)) return false;
          
          // Search filter
          if (searchInput && !name.includes(searchInput) && !description.includes(searchInput)) return false;
          
          return true;
        });

        // Sort
        visibleCards.sort((a, b) => {
          const aName = a.getAttribute('data-name') || '';
          const bName = b.getAttribute('data-name') || '';
          const aInstalled = parseInt(a.getAttribute('data-installed') || '0');
          const bInstalled = parseInt(b.getAttribute('data-installed') || '0');
          const aUpdated = parseInt(a.getAttribute('data-updated') || '0');
          const bUpdated = parseInt(b.getAttribute('data-updated') || '0');
          const aDownloads = parseInt(a.getAttribute('data-downloads') || '0');
          const bDownloads = parseInt(b.getAttribute('data-downloads') || '0');
          const aRating = parseFloat(a.getAttribute('data-rating') || '0');
          const bRating = parseFloat(b.getAttribute('data-rating') || '0');

          switch (sortValue) {
            case 'name-desc': return bName.localeCompare(aName);
            case 'newest': return bInstalled - aInstalled;
            case 'updated': return bUpdated - aUpdated;
            case 'popular': return bDownloads - aDownloads;
            case 'rating': return bRating - aRating;
            case 'name-asc':
            default: return aName.localeCompare(bName);
          }
        });

        // Re-append
        pluginCards.forEach(card => card.style.display = 'none'); // Hide all first
        
        // If no results
        let noResultsMsg = document.getElementById('no-results-message');
        if (visibleCards.length === 0) {
          if (!noResultsMsg) {
            noResultsMsg = document.createElement('div');
            noResultsMsg.id = 'no-results-message';
            noResultsMsg.className = 'col-span-full text-center py-12 bg-zinc-50 dark:bg-zinc-800/50 rounded-lg border border-dashed border-zinc-300 dark:border-zinc-700';
            noResultsMsg.innerHTML = \`
              <div class="flex flex-col items-center">
                <svg class="w-12 h-12 text-zinc-400 dark:text-zinc-600 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-1">No plugins found</h3>
                <p class="text-sm text-zinc-500 dark:text-zinc-400">Try adjusting your filters or search terms</p>
              </div>
            \`;
            pluginsGrid.appendChild(noResultsMsg);
          }
          noResultsMsg.style.display = '';
        } else {
          if (noResultsMsg) noResultsMsg.style.display = 'none';
          visibleCards.forEach(card => {
            card.style.display = '';
            pluginsGrid.appendChild(card); // Re-appending moves it to the end, effectively sorting
          });
        }
      }
    </script>

    <!-- Confirmation Dialogs -->
    ${renderConfirmationDialog({
      id: 'uninstall-plugin-confirm',
      title: 'Uninstall Plugin',
      message: 'Are you sure you want to uninstall this plugin? This action cannot be undone.',
      confirmText: 'Uninstall',
      cancelText: 'Cancel',
      iconColor: 'red',
      confirmClass: 'bg-red-500 hover:bg-red-400',
      onConfirm: 'performUninstallPlugin()',
    })}

    ${getConfirmationDialogScript()}
  `;

  const layoutData: AdminLayoutCatalystData = {
    title: 'Plugins',
    pageTitle: 'Plugin Management',
    currentPath: '/admin/plugins',
    user: data.user,
    version: data.version,
    content: pageContent,
  };

  return renderAdminLayoutCatalyst(layoutData);
}

function renderPluginCard(plugin: Plugin): string {
  const statusColors = {
    active:
      'bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 ring-emerald-600/20',
    inactive: 'bg-zinc-50 dark:bg-zinc-500/10 text-zinc-700 dark:text-zinc-400 ring-zinc-600/20',
    error: 'bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400 ring-red-600/20',
    uninstalled: 'bg-zinc-50 dark:bg-zinc-500/10 text-zinc-600 dark:text-zinc-500 ring-zinc-600/20',
  };

  const statusIcons = {
    active:
      '<div class="w-1.5 h-1.5 bg-emerald-500 dark:bg-emerald-400 rounded-full mr-1.5"></div>',
    inactive: '<div class="w-1.5 h-1.5 bg-zinc-500 dark:bg-zinc-400 rounded-full mr-1.5"></div>',
    error: '<div class="w-1.5 h-1.5 bg-red-500 dark:bg-red-400 rounded-full mr-1.5"></div>',
    uninstalled: '<div class="w-1.5 h-1.5 bg-zinc-400 dark:bg-zinc-600 rounded-full mr-1.5"></div>',
  };

  // Core system plugins that cannot be deactivated
  const criticalCorePlugins = ['core-auth', 'core-media'];
  const canToggle = !criticalCorePlugins.includes(plugin.id);

  let actionButton = '';
  if (plugin.status === 'uninstalled') {
    actionButton = `<button onclick="event.stopPropagation(); installPlugin('${plugin.name}')" class="w-full sm:w-auto bg-zinc-900 dark:bg-white hover:bg-zinc-800 dark:hover:bg-zinc-100 text-white dark:text-zinc-900 px-3 py-1.5 rounded-md text-xs font-medium transition-colors shadow-sm">Install</button>`;
  } else {
    const isActive = plugin.status === 'active';
    const action = isActive ? 'deactivate' : 'activate';
    // Use bg-emerald-600 for active, bg-zinc-200 (light) / bg-zinc-700 (dark) for inactive
    const bgClass = isActive ? 'bg-emerald-600' : 'bg-zinc-200 dark:bg-zinc-700';
    const translateClass = isActive ? 'translate-x-5' : 'translate-x-0';

    if (canToggle) {
      actionButton = `
      <button onclick="event.stopPropagation(); togglePlugin('${plugin.id}', '${action}', event)" type="button" class="${bgClass} relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-emerald-600 focus:ring-offset-2 toggle-button" role="switch" aria-checked="${isActive}">
        <span class="sr-only">Toggle plugin</span>
        <span aria-hidden="true" class="${translateClass} pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out toggle-knob"></span>
      </button>
      `;
    } else {
      // Critical core plugins cannot be toggled
      actionButton = `
      <div class="relative inline-flex h-6 w-11 flex-shrink-0 cursor-not-allowed rounded-full border-2 border-transparent bg-emerald-600/50 opacity-50" title="Core plugin cannot be disabled">
        <span class="translate-x-5 pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0"></span>
      </div>
      `;
    }
  }

  return `
    <div class="plugin-card flex flex-col h-full rounded-md bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/10 dark:ring-white/10 p-5 transition-all hover:shadow-md cursor-pointer"
      onclick="openPluginSettings('${plugin.id}')"
      data-category="${plugin.category}"
      data-status="${plugin.status}"
      data-name="${plugin.displayName}"
      data-description="${plugin.description}"
      data-downloads="${plugin.downloadCount || 0}"
      data-rating="${plugin.rating || 0}">
      <div class="flex items-start justify-between mb-4">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-md flex items-center justify-center bg-zinc-50 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400 ring-1 ring-inset ring-zinc-200 dark:ring-zinc-700/50">
            ${plugin.icon || getDefaultPluginIcon(plugin.category)}
          </div>
          <div>
            <div class="flex items-center gap-2">
              <h3 class="text-sm font-semibold text-zinc-900 dark:text-white">${plugin.displayName}</h3>
              <span class="status-badge inline-flex items-center rounded-full px-1.5 py-0.5 text-[10px] font-medium ring-1 ring-inset ${statusColors[plugin.status]}">
                ${statusIcons[plugin.status]}${plugin.status.charAt(0).toUpperCase() + plugin.status.slice(1)}
              </span>
            </div>
            <p class="text-xs text-zinc-500 dark:text-zinc-400">v${plugin.version} • ${plugin.author}</p>
          </div>
        </div>
        
        <div class="flex items-center gap-1">
          ${
            !plugin.isCore && plugin.status !== 'uninstalled'
              ? `
          <button onclick="event.stopPropagation(); uninstallPlugin('${plugin.id}')" class="text-zinc-400 hover:text-red-600 dark:text-zinc-500 dark:hover:text-red-400 p-1.5 rounded-md hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors" title="Uninstall Plugin">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
            </svg>
          </button>
          `
              : ''
          }
        </div>
      </div>

      <p class="text-zinc-600 dark:text-zinc-400 text-sm mb-4 line-clamp-2 flex-grow">${plugin.description}</p>

      <div class="flex flex-wrap items-center gap-2 mb-5">
        <span class="inline-flex items-center rounded-md bg-zinc-100 dark:bg-zinc-800 px-2 py-1 text-xs font-medium text-zinc-600 dark:text-zinc-400">
          ${plugin.category}
        </span>
        ${plugin.isCore ? '<span class="inline-flex items-center rounded-md bg-zinc-100 dark:bg-zinc-800 px-2 py-1 text-xs font-medium text-zinc-600 dark:text-zinc-400">Core</span>' : ''}
        
        ${
          (plugin.dependencies &&
            plugin.dependencies
              .map(
                (dep) => `
          <span class="inline-flex items-center rounded-md bg-zinc-100 dark:bg-zinc-800 px-2 py-1 text-xs font-medium text-zinc-600 dark:text-zinc-400">
            ${dep}
          </span>
        `,
              )
              .join('')) ||
          ''
        }
      </div>

      <div class="flex items-center justify-between pt-4 border-t border-zinc-100 dark:border-zinc-800 mt-auto">
        <div class="flex gap-2">
          ${actionButton}
        </div>
      </div>
    </div>
  `;
}

function getDefaultPluginIcon(category: string): string {
  const iconColor = 'text-zinc-600 dark:text-zinc-400';

  const icons: Record<string, string> = {
    content: `
      <svg class="w-6 h-6 ${iconColor}" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 0 0-3.375-3.375h-1.5A1.125 1.125 0 0 1 13.5 7.125v-1.5a3.375 3.375 0 0 0-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 0 0-9-9Z" />
      </svg>
    `,
    media: `
      <svg class="w-6 h-6 ${iconColor}" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" d="m2.25 15.75 5.159-5.159a2.25 2.25 0 0 1 3.182 0l5.159 5.159m-1.5-1.5 1.409-1.409a2.25 2.25 0 0 1 3.182 0l2.909 2.909m-18 3.75h16.5a1.5 1.5 0 0 0 1.5-1.5V6a1.5 1.5 0 0 0-1.5-1.5H3.75A1.5 1.5 0 0 0 2.25 6v12a1.5 1.5 0 0 0 1.5 1.5Zm10.5-11.25h.008v.008h-.008V8.25Zm.375 0a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0Z" />
      </svg>
    `,
    seo: `
      <svg class="w-6 h-6 ${iconColor}" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" />
      </svg>
    `,
    analytics: `
      <svg class="w-6 h-6 ${iconColor}" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 0 1 3 19.875v-6.75ZM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 0 1-1.125-1.125V8.625ZM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 0 1-1.125-1.125V4.125Z" />
      </svg>
    `,
    ecommerce: `
      <svg class="w-6 h-6 ${iconColor}" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" d="M2.25 3h1.386c.51 0 .955.343 1.087.835l.383 1.437M7.5 14.25a3 3 0 0 0-3 3h15.75m-12.75-3h11.218c1.121-2.3 2.1-4.684 2.924-7.138a60.114 60.114 0 0 0-16.536-1.84M7.5 14.25 5.106 5.272M6 20.25a.75.75 0 1 1-1.5 0 .75.75 0 0 1 1.5 0Zm12.75 0a.75.75 0 1 1-1.5 0 .75.75 0 0 1 1.5 0Z" />
      </svg>
    `,
    email: `
      <svg class="w-6 h-6 ${iconColor}" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 0 1-2.25 2.25h-15a2.25 2.25 0 0 1-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0 0 19.5 4.5h-15a2.25 2.25 0 0 0-2.25 2.25m19.5 0v.243a2.25 2.25 0 0 1-1.07 1.916l-7.5 4.615a2.25 2.25 0 0 1-2.36 0L3.32 8.91a2.25 2.25 0 0 1-1.07-1.916V6.75" />
      </svg>
    `,
    workflow: `
      <svg class="w-6 h-6 ${iconColor}" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0 3.181 3.183a8.25 8.25 0 0 0 13.803-3.7M4.031 9.865a8.25 8.25 0 0 1 13.803-3.7l3.181 3.182m0-4.991v4.99" />
      </svg>
    `,
    security: `
      <svg class="w-6 h-6 ${iconColor}" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" />
      </svg>
    `,
    social: `
      <svg class="w-6 h-6 ${iconColor}" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" d="M18 18.72a9.094 9.094 0 0 0 3.741-.479 3 3 0 0 0-4.682-2.72m.94 3.198.001.031c0 .225-.012.447-.037.666A11.944 11.944 0 0 1 12 21c-2.17 0-4.207-.576-5.963-1.584A6.062 6.062 0 0 1 6 18.719m12 0a5.971 5.971 0 0 0-.941-3.197m0 0A5.995 5.995 0 0 0 12 12.75a5.995 5.995 0 0 0-5.058 2.772m0 0a3 3 0 0 0-4.681 2.72 8.986 8.986 0 0 0 3.74.477m.94-3.197a5.971 5.971 0 0 0-.94 3.197M15 6.75a3 3 0 1 1-6 0 3 3 0 0 1 6 0Zm6 3a2.25 2.25 0 1 1-4.5 0 2.25 2.25 0 0 1 4.5 0Zm-13.5 0a2.25 2.25 0 1 1-4.5 0 2.25 2.25 0 0 1 4.5 0Z" />
      </svg>
    `,
    utility: `
      <svg class="w-6 h-6 ${iconColor}" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.325.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 0 1 1.37.49l1.296 2.247a1.125 1.125 0 0 1-.26 1.431l-1.003.827c-.293.241-.438.613-.43.992a7.723 7.723 0 0 1 0 .255c-.008.378.137.75.43.991l1.004.827c.424.35.534.955.26 1.43l-1.298 2.247a1.125 1.125 0 0 1-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.47 6.47 0 0 1-.22.128c-.331.183-.581.495-.644.869l-.213 1.281c-.09.543-.56.94-1.11.94h-2.594c-.55 0-1.019-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 0 1-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 0 1-1.369-.49l-1.297-2.247a1.125 1.125 0 0 1 .26-1.431l1.004-.827c.292-.24.437-.613.43-.991a6.932 6.932 0 0 1 0-.255c.007-.38-.138-.751-.43-.992l-1.004-.827a1.125 1.125 0 0 1-.26-1.43l1.297-2.247a1.125 1.125 0 0 1 1.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.086.22-.128.332-.183.582-.495.644-.869l.214-1.28Z" />
        <path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z" />
      </svg>
    `,
  };

  const iconKey = category.toLowerCase() as keyof typeof icons;
  return icons[iconKey] || icons['utility'] || '';
}

// Mock data generator
export function generateMockPlugins(): Plugin[] {
  return [
    {
      id: '1',
      name: 'seo-optimizer',
      displayName: 'SEO Optimizer',
      description:
        'Advanced SEO optimization tools including meta tag management, sitemap generation, and analytics integration. Boost your search engine rankings with automated optimizations.',
      version: '2.1.4',
      author: 'SonicJS Team',
      status: 'active',
      category: 'seo',
      icon: `<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>`,
      downloadCount: 15420,
      rating: 4.8,
      lastUpdated: '2 days ago',
      dependencies: ['analytics-plugin'],
      permissions: ['read:content', 'write:meta'],
      isCore: true,
    },
    {
      id: '2',
      name: 'image-optimizer',
      displayName: 'Image Optimizer',
      description:
        'Automatically compress and optimize images on upload. Supports WebP conversion, lazy loading, and responsive image generation for better performance.',
      version: '1.5.2',
      author: 'MediaPro',
      status: 'active',
      category: 'media',
      icon: `<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>`,
      downloadCount: 8930,
      rating: 4.6,
      lastUpdated: '1 week ago',
      dependencies: [],
      permissions: ['write:media', 'read:settings'],
    },
    {
      id: '3',
      name: 'backup-manager',
      displayName: 'Backup Manager',
      description:
        'Automated backup solution for content and media files. Schedule regular backups to cloud storage with encryption and restore capabilities.',
      version: '3.0.1',
      author: 'BackupCorp',
      status: 'inactive',
      category: 'utilities',
      icon: `<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"/></svg>`,
      downloadCount: 12450,
      rating: 4.9,
      lastUpdated: '3 days ago',
      dependencies: ['cloud-storage'],
      permissions: ['read:all', 'write:backups'],
    },
    {
      id: '4',
      name: 'security-scanner',
      displayName: 'Security Scanner',
      description:
        'Real-time security monitoring and vulnerability scanning. Detects malware, suspicious activities, and provides security recommendations.',
      version: '1.2.8',
      author: 'SecureWeb',
      status: 'error',
      category: 'security',
      icon: `<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>`,
      downloadCount: 5680,
      rating: 4.3,
      lastUpdated: '5 days ago',
      dependencies: ['security-core'],
      permissions: ['read:logs', 'read:files', 'write:security'],
    },
    {
      id: '5',
      name: 'social-share',
      displayName: 'Social Share',
      description:
        'Easy social media sharing buttons and Open Graph meta tag generation. Supports all major social platforms with customizable styling.',
      version: '2.3.0',
      author: 'SocialPlus',
      status: 'active',
      category: 'content',
      icon: `<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z"/></svg>`,
      downloadCount: 22100,
      rating: 4.7,
      lastUpdated: '4 days ago',
      dependencies: [],
      permissions: ['read:content', 'write:meta'],
    },
    {
      id: '6',
      name: 'analytics-pro',
      displayName: 'Analytics Pro',
      description:
        'Advanced analytics dashboard with custom tracking events, conversion funnels, and detailed visitor insights. GDPR compliant with privacy controls.',
      version: '4.1.2',
      author: 'AnalyticsPro Inc',
      status: 'active',
      category: 'seo',
      icon: `<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>`,
      downloadCount: 18750,
      rating: 4.9,
      lastUpdated: '1 day ago',
      dependencies: ['gdpr-compliance'],
      permissions: ['read:analytics', 'write:tracking', 'read:users'],
    },
    {
      id: '7',
      name: 'form-builder',
      displayName: 'Advanced Form Builder',
      description:
        'Drag-and-drop form builder with conditional logic, file uploads, payment integration, and email notifications. Perfect for contact forms and surveys.',
      version: '1.8.5',
      author: 'FormWorks',
      status: 'inactive',
      category: 'content',
      icon: `<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>`,
      downloadCount: 9870,
      rating: 4.4,
      lastUpdated: '1 week ago',
      dependencies: ['email-service'],
      permissions: ['write:forms', 'read:submissions', 'send:emails'],
    },
    {
      id: '8',
      name: 'cache-optimizer',
      displayName: 'Cache Optimizer',
      description:
        'Intelligent caching system with Redis support, CDN integration, and automatic cache invalidation. Dramatically improves site performance.',
      version: '2.7.3',
      author: 'SpeedBoost',
      status: 'active',
      category: 'utilities',
      icon: `<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>`,
      downloadCount: 13240,
      rating: 4.8,
      lastUpdated: '6 days ago',
      dependencies: ['redis-connector'],
      permissions: ['read:cache', 'write:cache', 'manage:cdn'],
      isCore: true,
    },
    {
      id: '9',
      name: 'multilingual',
      displayName: 'Multilingual Support',
      description:
        'Complete internationalization solution with automatic translation, language detection, and localized content management for global websites.',
      version: '3.2.1',
      author: 'GlobalWeb',
      status: 'active',
      category: 'content',
      icon: `<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 5h12M9 3v2m1.048 9.5A18.022 18.022 0 016.412 9m6.088 9h7M11 21l5-10 5 10M12.751 5C11.783 10.77 8.07 15.61 3 18.129"/></svg>`,
      downloadCount: 7650,
      rating: 4.5,
      lastUpdated: '2 weeks ago',
      dependencies: ['translation-api'],
      permissions: ['read:content', 'write:translations', 'manage:languages'],
    },
  ];
}
