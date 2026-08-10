import { renderAdminLayout, AdminLayoutData } from '../layouts/admin-layout-v2.template'
import { renderAuthSettingsForm } from '../components/auth-settings-form.template'
import type { AuthSettings } from '../../services/auth-validation'
import { getPluginDefinition } from '../../services/plugin-definition-registry'

/**
 * Escape HTML attribute values to prevent XSS
 */
function escapeHtmlAttr(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

export interface PluginSettings {
  [key: string]: any
}

export interface PluginActivity {
  id: string
  action: string
  message: string
  timestamp: number
  user?: string
}

export interface PluginSettingsPageData {
  plugin: {
    id: string
    name: string
    displayName: string
    description: string
    version: string
    author: string
    status: 'active' | 'inactive' | 'error'
    category: string
    icon: string
    downloadCount?: number
    rating?: number
    lastUpdated: string
    dependencies?: string[]
    permissions?: string[]
    isCore?: boolean
    settings?: PluginSettings
    /** Live user-profile config (user-profiles plugin only) — null when defineUserProfile() not called. */
    profileConfig?: {
      fields: Array<{ name: string; label: string; type: string; required: boolean }>
      registrationFields: string[]
    } | null
  }
  activity?: PluginActivity[]
  user?: {
    name: string
    email: string
    role: string
  }
  /** Data returned by the plugin's settingsTabContent.loadData(), if defined. */
  settingsTabData?: any
}

export function renderPluginSettingsPage(data: PluginSettingsPageData): string {
  const { plugin, activity = [], user, settingsTabData } = data
  // true only when the plugin has at least one user-configurable setting key
  // (_-prefixed keys are internal metadata, not settings the user can edit)
  const pluginDef = getPluginDefinition(plugin.id || plugin.name)
  const pluginId = plugin.id || plugin.name
  const hasUserSettings = pluginDef?.settingsTabContent != null ||
    Object.keys(plugin.settings || {}).some(k => !k.startsWith('_')) ||
    hasCustomSettingsComponent(pluginId)
  const defaultTab = hasUserSettings ? 'settings' : 'info'


  const pageContent = `
    <div class="w-full px-4 sm:px-6 lg:px-8 py-6">
      <!-- Header with Back Button -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6">
        <div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">Plugin Settings</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">
            ${plugin.description}
          </p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16 flex items-center gap-3">
          <a href="/admin/plugins" class="inline-flex items-center justify-center rounded-lg bg-white dark:bg-zinc-800 px-3.5 py-2.5 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors shadow-sm">
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/>
            </svg>
            Back to Plugins
          </a>
          ${plugin.settings?._adminPath ? `
          <a
            href="${plugin.settings._adminPath}"
            class="inline-flex items-center justify-center gap-1.5 rounded-lg bg-gradient-to-r from-cyan-500 to-purple-600 hover:from-cyan-400 hover:to-purple-500 px-3.5 py-2.5 text-sm font-semibold text-white shadow-sm transition-all duration-200"
          >
            <svg class="-ml-0.5 h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
            </svg>
            View Page
          </a>
          ` : ''}
        </div>
      </div>

      <!-- Plugin Header -->
      <div class="backdrop-blur-md bg-black/20 rounded-xl border border-white/10 shadow-xl p-6 mb-6">
        <div class="flex items-start justify-between">
          <div class="flex items-center gap-4">
            <div class="w-16 h-16 bg-gradient-to-br from-blue-500 to-purple-600 rounded-xl flex items-center justify-center text-white text-2xl font-bold">
              ${plugin.icon || plugin.displayName.charAt(0).toUpperCase()}
            </div>
            <div>
              <h2 class="text-2xl font-semibold text-white mb-1">${plugin.displayName}</h2>
              <div class="flex items-center gap-4 text-sm text-gray-400 mt-2">
                <span>v${plugin.version}</span>
                <span>by ${plugin.author}</span>
                <span>${plugin.category}</span>
                ${plugin.downloadCount ? `<span>${plugin.downloadCount.toLocaleString()} downloads</span>` : ''}
                ${plugin.rating ? `<span>★ ${plugin.rating}</span>` : ''}
              </div>
            </div>
          </div>

          <div class="flex items-center gap-3">
            ${renderStatusBadge(plugin.status)}
            ${renderToggleButton(plugin)}
          </div>
        </div>
      </div>

      <!-- Tabs -->
      <div class="mb-6">
        <nav class="flex space-x-8" aria-label="Tabs">
          ${hasUserSettings ? `
          <a href="#settings" onclick="showTab('settings')" id="settings-tab" class="tab-button border-b-2 border-transparent py-2 px-1 text-sm font-medium text-gray-400 hover:text-gray-300">
            Settings
          </a>
          ` : ''}
          <a href="#info" onclick="showTab('info')" id="info-tab" class="tab-button border-b-2 border-transparent py-2 px-1 text-sm font-medium text-gray-400 hover:text-gray-300">
            Information
          </a>
          <a href="#activity" onclick="showTab('activity')" id="activity-tab" class="tab-button border-b-2 border-transparent py-2 px-1 text-sm font-medium text-gray-400 hover:text-gray-300">
            Activity Log
          </a>
        </nav>
      </div>

      <!-- Tab Content -->
      <div id="tab-content">
        <!-- Settings Tab -->
        <div id="settings-content" class="tab-content hidden">
          ${hasUserSettings ? renderSettingsTab(plugin, settingsTabData) : ''}
        </div>

        <!-- Activity Tab -->
        <div id="activity-content" class="tab-content hidden">
          ${renderActivityTab(activity)}
        </div>

        <!-- Information Tab -->
        <div id="info-content" class="tab-content hidden">
          ${renderInformationTab(plugin)}
        </div>
      </div>
    </div>

    <script>
      const VALID_TABS = [${hasUserSettings ? "'settings', " : ""}'activity', 'info'];

      function showTab(tabName) {
        if (!VALID_TABS.includes(tabName)) tabName = '${defaultTab}';

        document.querySelectorAll('.tab-content').forEach(content => {
          content.classList.add('hidden');
        });

        document.querySelectorAll('.tab-button').forEach(tab => {
          tab.classList.remove('active', 'border-blue-400', 'text-blue-400');
          tab.classList.add('border-transparent', 'text-gray-400');
        });

        const contentEl = document.getElementById(tabName + '-content');
        if (contentEl) contentEl.classList.remove('hidden');

        const activeTab = document.getElementById(tabName + '-tab');
        if (activeTab) {
          activeTab.classList.add('active', 'border-blue-400', 'text-blue-400');
          activeTab.classList.remove('border-transparent', 'text-gray-400');
        }

        if (window.location.hash !== '#' + tabName) {
          history.replaceState(null, '', '#' + tabName);
        }
      }

      function initTabFromHash() {
        const hash = window.location.hash.replace('#', '');
        showTab(VALID_TABS.includes(hash) ? hash : '${defaultTab}');
      }

      window.addEventListener('hashchange', initTabFromHash);
      initTabFromHash();

      async function togglePlugin(pluginId, action) {
        const button = event.target;
        const originalText = button.textContent;
        button.disabled = true;
        button.textContent = action === 'activate' ? 'Activating...' : 'Deactivating...';
        
        try {
          const response = await fetch(\`/admin/plugins/\${pluginId}/\${action}\`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            }
          });
          
          const result = await response.json();
          
          if (result.success) {
            showNotification(\`Plugin \${action}d successfully\`, 'success');
            setTimeout(() => location.reload(), 1000);
          } else {
            throw new Error(result.error || \`Failed to \${action} plugin\`);
          }
        } catch (error) {
          showNotification(error.message, 'error');
          button.textContent = originalText;
          button.disabled = false;
        }
      }

      async function saveSettings() {
        const form = document.getElementById('settings-form');
        const formData = new FormData(form);
        const isAuthPlugin = '${plugin.id}' === 'core-auth';
        const isOAuthPlugin = '${plugin.id}' === 'oauth-providers';
        let settings = {};

        if (isOAuthPlugin) {
          // Build nested provider settings structure
          const getVal = id => (document.getElementById(id) || {}).value || '';
          const getChecked = id => !!(document.getElementById(id) || {}).checked;
          settings = {
            providers: {
              github: {
                clientId: getVal('oauth_github_clientId'),
                clientSecret: getVal('oauth_github_clientSecret'),
                enabled: getChecked('oauth_github_enabled'),
              },
              google: {
                clientId: getVal('oauth_google_clientId'),
                clientSecret: getVal('oauth_google_clientSecret'),
                enabled: getChecked('oauth_google_enabled'),
              },
            }
          };
        } else if (isAuthPlugin) {
          // Handle nested auth settings structure
          settings = {
            requiredFields: {},
            validation: {
              passwordRequirements: {}
            },
            registration: {}
          };

          for (let [key, value] of formData.entries()) {
            const input = form.querySelector(\`[name="\${key}"]\`);
            const fieldValue = input.type === 'checkbox' ? input.checked :
                             input.type === 'number' ? parseInt(value) || 0 : value;

            // Parse nested field names like "requiredFields_email_required"
            if (key.startsWith('requiredFields_')) {
              const parts = key.replace('requiredFields_', '').split('_');
              const fieldName = parts[0];
              const propName = parts[1];

              if (!settings.requiredFields[fieldName]) {
                settings.requiredFields[fieldName] = { type: 'text', label: '' };
              }
              settings.requiredFields[fieldName][propName] = fieldValue;
            } else if (key.startsWith('validation_passwordRequirements_')) {
              const propName = key.replace('validation_passwordRequirements_', '');
              settings.validation.passwordRequirements[propName] = fieldValue;
            } else if (key.startsWith('validation_')) {
              const propName = key.replace('validation_', '');
              // Invert the allowDuplicateUsernames logic
              if (propName === 'allowDuplicateUsernames') {
                settings.validation[propName] = !fieldValue;
              } else {
                settings.validation[propName] = fieldValue;
              }
            } else if (key.startsWith('registration_')) {
              const propName = key.replace('registration_', '');
              settings.registration[propName] = fieldValue;
            }
          }
        } else {
          // Handle regular plugin settings
          for (let [key, value] of formData.entries()) {
            if (key.startsWith('setting_')) {
              const settingKey = key.replace('setting_', '');

              const input = form.querySelector(\`[name="\${key}"]\`);
              if (input.type === 'checkbox') {
                settings[settingKey] = input.checked;
              } else if (input.type === 'number') {
                settings[settingKey] = parseInt(value) || 0;
              } else {
                settings[settingKey] = value;
              }
            }
          }
        }

        const saveButton = document.getElementById('save-button');
        saveButton.disabled = true;
        saveButton.textContent = 'Saving...';

        try {
          const response = await fetch(\`/admin/plugins/${plugin.id}/settings\`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(settings)
          });

          const result = await response.json();

          if (result.success) {
            showNotification('Settings saved successfully', 'success');
            // Reload page after 1 second to show updated settings
            setTimeout(() => location.reload(), 1000);
          } else {
            throw new Error(result.error || 'Failed to save settings');
          }
        } catch (error) {
          showNotification(error.message, 'error');
        } finally {
          saveButton.disabled = false;
          saveButton.textContent = 'Save Settings';
        }
      }

      function showNotification(message, type) {
        const notification = document.createElement('div');
        const bgColor = type === 'success' ? 'bg-green-600' : type === 'error' ? 'bg-red-600' : 'bg-blue-600';
        notification.className = \`fixed top-4 right-4 px-4 py-2 rounded-lg text-white z-50 \${bgColor}\`;
        notification.textContent = message;
        document.body.appendChild(notification);
        
        setTimeout(() => {
          notification.remove();
        }, 3000);
      }
    </script>
  `

  const layoutData: AdminLayoutData = {
    title: `${plugin.displayName} Settings`,
    pageTitle: `${plugin.displayName} Settings`,
    currentPath: `/admin/plugins/${plugin.id}`,
    user,
    content: pageContent
  }

  return renderAdminLayout(layoutData)
}

function renderStatusBadge(status: string): string {
  const statusColors: Record<string, string> = {
    active: 'bg-green-900/50 text-green-300 border-green-600/30',
    inactive: 'bg-gray-800/50 text-gray-400 border-gray-600/30',
    error: 'bg-red-900/50 text-red-300 border-red-600/30'
  }

  const statusIcons: Record<string, string> = {
    active: '<div class="w-2 h-2 bg-green-400 rounded-full mr-2"></div>',
    inactive: '<div class="w-2 h-2 bg-gray-500 rounded-full mr-2"></div>',
    error: '<div class="w-2 h-2 bg-red-400 rounded-full mr-2"></div>'
  }

  return `
    <span class="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${statusColors[status] || statusColors.inactive} border">
      ${statusIcons[status] || statusIcons.inactive}${status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  `
}

function renderToggleButton(plugin: any): string {
  if (plugin.isCore) {
    return '<span class="text-sm text-gray-400">Core Plugin</span>'
  }

  return plugin.status === 'active' 
    ? `<button onclick="togglePlugin('${plugin.id}', 'deactivate')" class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">Deactivate</button>`
    : `<button onclick="togglePlugin('${plugin.id}', 'activate')" class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">Activate</button>`
}

function renderSettingsTab(plugin: any, settingsTabData?: any): string {
  const settings = plugin.settings || {}
  const pluginId = plugin.id || plugin.name
  const hasUserKeys = Object.keys(settings).some(k => !k.startsWith('_'))

  // Check plugin definition registry first (plugins self-register via definePlugin settingsTabContent)
  const pluginDef = getPluginDefinition(pluginId)
  if (pluginDef?.settingsTabContent) {
    return pluginDef.settingsTabContent.render({ plugin, settings, data: settingsTabData })
  }

  // Legacy: hardcoded per-plugin renderers
  const customRenderer = pluginSettingsComponents[pluginId]
  if (customRenderer) {
    return `
      <div class="backdrop-blur-md bg-black/20 rounded-xl border border-white/10 shadow-xl p-6">
        ${customRenderer(plugin, settings)}

        <div class="flex items-center justify-end pt-6 border-t border-white/10 mt-6">
          <button
            type="button"
            id="save-button"
            onclick="saveSettings()"
            class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg font-medium transition-colors"
          >
            Save Settings
          </button>
        </div>
      </div>
    `
  }

  const isAuthPlugin = plugin.id === 'core-auth' || plugin.name === 'core-auth'
  const isTurnstilePlugin = plugin.id === 'turnstile' || plugin.name === 'turnstile'

  return `

    <div class="backdrop-blur-md bg-black/20 rounded-xl border border-white/10 shadow-xl p-6">
      ${isAuthPlugin ? `
        <h2 class="text-xl font-semibold text-white mb-4">Authentication Settings</h2>
        <p class="text-gray-400 mb-6">Configure user registration fields and validation rules.</p>
      ` : isTurnstilePlugin ? `
        <h2 class="text-xl font-semibold text-white mb-4">Cloudflare Turnstile Settings</h2>
        <p class="text-gray-400 mb-6">Configure CAPTCHA-free bot protection for your forms.</p>
      ` : `
        <h2 class="text-xl font-semibold text-white mb-4">Plugin Settings</h2>
      `}

      <form id="settings-form" class="space-y-6">
        ${isAuthPlugin && hasUserKeys
          ? renderAuthSettingsForm(settings as AuthSettings)
          : isTurnstilePlugin && hasUserKeys
            ? renderTurnstileSettingsForm(settings)
            : hasUserKeys
              ? renderSettingsFields(settings)
              : renderNoSettings(plugin)
        }

        ${hasUserKeys ? `
        <div class="flex items-center justify-end pt-6 border-t border-white/10">
          <button
            type="button"
            id="save-button"
            onclick="saveSettings()"
            class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg font-medium transition-colors"
          >
            Save Settings
          </button>
        </div>
        ` : ''}
      </form>
    </div>
  `
}

function renderSettingsFields(settings: PluginSettings): string {
  return Object.entries(settings).filter(([key]) => !key.startsWith('_')).map(([key, value]) => {
    const fieldId = `setting_${key}`
    const displayName = key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())
    
    if (typeof value === 'boolean') {
      return `
        <div class="flex items-center justify-between">
          <div>
            <label for="${fieldId}" class="text-sm font-medium text-gray-300">${displayName}</label>
            <p class="text-xs text-gray-400">Enable or disable this feature</p>
          </div>
          <label class="relative inline-flex items-center cursor-pointer">
            <input type="checkbox" name="${fieldId}" id="${fieldId}" ${value ? 'checked' : ''} class="sr-only peer">
            <div class="w-11 h-6 bg-gray-600 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
          </label>
        </div>
      `
    } else if (typeof value === 'number') {
      return `
        <div>
          <label for="${fieldId}" class="block text-sm font-medium text-gray-300 mb-2">${displayName}</label>
          <input 
            type="number" 
            name="${fieldId}" 
            id="${fieldId}" 
            value="${value}"
            class="backdrop-blur-sm bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white placeholder-gray-300 focus:border-blue-400 focus:outline-none transition-colors w-full"
          >
        </div>
      `
    } else {
      return `
        <div>
          <label for="${fieldId}" class="block text-sm font-medium text-gray-300 mb-2">${displayName}</label>
          <input 
            type="text" 
            name="${fieldId}" 
            id="${fieldId}" 
            value="${value}"
            class="backdrop-blur-sm bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white placeholder-gray-300 focus:border-blue-400 focus:outline-none transition-colors w-full"
          >
        </div>
      `
    }
  }).join('')
}

function renderTurnstileSettingsForm(settings: any): string {
  const inputClass = "backdrop-blur-sm bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white placeholder-gray-300 focus:border-blue-400 focus:outline-none transition-colors w-full"
  const selectClass = "backdrop-blur-sm bg-zinc-800 border border-white/20 rounded-lg px-3 py-2 text-white focus:border-blue-400 focus:outline-none transition-colors w-full [&>option]:bg-zinc-800 [&>option]:text-white"
  
  return `
    <!-- Enable Toggle -->
    <div class="flex items-center justify-between">
      <div>
        <label for="setting_enabled" class="text-sm font-medium text-gray-300">Enable Turnstile</label>
        <p class="text-xs text-gray-400">Enable or disable Turnstile verification globally</p>
      </div>
      <label class="relative inline-flex items-center cursor-pointer">
        <input type="checkbox" name="setting_enabled" id="setting_enabled" ${settings.enabled ? 'checked' : ''} class="sr-only peer">
        <div class="w-11 h-6 bg-gray-600 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
      </label>
    </div>

    <!-- Site Key -->
    <div>
      <label for="setting_siteKey" class="block text-sm font-medium text-gray-300 mb-2">Site Key</label>
      <input type="text" name="setting_siteKey" id="setting_siteKey" value="${escapeHtmlAttr(settings.siteKey || '')}" placeholder="0x4AAAAAAAA..." class="${inputClass}">
      <p class="text-xs text-gray-400 mt-1">Your Cloudflare Turnstile site key (public)</p>
    </div>

    <!-- Secret Key -->
    <div>
      <label for="setting_secretKey" class="block text-sm font-medium text-gray-300 mb-2">Secret Key</label>
      <input type="password" name="setting_secretKey" id="setting_secretKey" value="${escapeHtmlAttr(settings.secretKey || '')}" placeholder="0x4AAAAAAAA..." class="${inputClass}">
      <p class="text-xs text-gray-400 mt-1">Your Cloudflare Turnstile secret key (private)</p>
    </div>

    <!-- Theme -->
    <div>
      <label for="setting_theme" class="block text-sm font-medium text-gray-300 mb-2">Widget Theme</label>
      <select name="setting_theme" id="setting_theme" class="${selectClass}" style="color: white; background-color: rgb(39, 39, 42);">
        <option value="auto" ${settings.theme === 'auto' ? 'selected' : ''} style="background-color: rgb(39, 39, 42); color: white;">Auto (matches page theme)</option>
        <option value="light" ${settings.theme === 'light' ? 'selected' : ''} style="background-color: rgb(39, 39, 42); color: white;">Light</option>
        <option value="dark" ${settings.theme === 'dark' ? 'selected' : ''} style="background-color: rgb(39, 39, 42); color: white;">Dark</option>
      </select>
      <p class="text-xs text-gray-400 mt-1">Visual appearance of the Turnstile widget</p>
    </div>

    <!-- Size -->
    <div>
      <label for="setting_size" class="block text-sm font-medium text-gray-300 mb-2">Widget Size</label>
      <select name="setting_size" id="setting_size" class="${selectClass}" style="color: white; background-color: rgb(39, 39, 42);">
        <option value="normal" ${settings.size === 'normal' ? 'selected' : ''} style="background-color: rgb(39, 39, 42); color: white;">Normal (300x65px)</option>
        <option value="compact" ${settings.size === 'compact' ? 'selected' : ''} style="background-color: rgb(39, 39, 42); color: white;">Compact (130x120px)</option>
      </select>
      <p class="text-xs text-gray-400 mt-1">Size of the Turnstile challenge widget</p>
    </div>

    <!-- Widget Mode -->
    <div>
      <label for="setting_mode" class="block text-sm font-medium text-gray-300 mb-2">Widget Mode</label>
      <select name="setting_mode" id="setting_mode" class="${selectClass}" style="color: white; background-color: rgb(39, 39, 42);">
        <option value="managed" ${(!settings.mode || settings.mode === 'managed') ? 'selected' : ''} style="background-color: rgb(39, 39, 42); color: white;">Managed (Recommended) - Adaptive challenge</option>
        <option value="non-interactive" ${settings.mode === 'non-interactive' ? 'selected' : ''} style="background-color: rgb(39, 39, 42); color: white;">Non-Interactive - Always visible, minimal friction</option>
        <option value="invisible" ${settings.mode === 'invisible' ? 'selected' : ''} style="background-color: rgb(39, 39, 42); color: white;">Invisible - No visible widget</option>
      </select>
      <p class="text-xs text-gray-400 mt-1"><strong>Managed:</strong> Shows challenge only when needed. <strong>Non-Interactive:</strong> Always shows but doesn't require interaction. <strong>Invisible:</strong> Runs in background without UI.</p>
    </div>

    <!-- Appearance (Pre-clearance) -->
    <div>
      <label for="setting_appearance" class="block text-sm font-medium text-gray-300 mb-2">Pre-clearance / Appearance</label>
      <select name="setting_appearance" id="setting_appearance" class="${selectClass}" style="color: white; background-color: rgb(39, 39, 42);">
        <option value="always" ${(!settings.appearance || settings.appearance === 'always') ? 'selected' : ''} style="background-color: rgb(39, 39, 42); color: white;">Always - Pre-clearance enabled (verifies immediately)</option>
        <option value="execute" ${settings.appearance === 'execute' ? 'selected' : ''} style="background-color: rgb(39, 39, 42); color: white;">Execute - Challenge on form submit</option>
        <option value="interaction-only" ${settings.appearance === 'interaction-only' ? 'selected' : ''} style="background-color: rgb(39, 39, 42); color: white;">Interaction Only - Only after user interaction</option>
      </select>
      <p class="text-xs text-gray-400 mt-1">Controls when Turnstile verification occurs. <strong>Always:</strong> Verifies immediately (pre-clearance). <strong>Execute:</strong> Verifies on form submit. <strong>Interaction Only:</strong> Only after user interaction.</p>
    </div>
  `
}

function renderNoSettings(plugin: any): string {
  // User Profiles plugin — profile fields are a code-defined data model, not UI settings.
  if (plugin.id === 'user-profiles' || plugin.name === 'user-profiles') {
    return renderUserProfilesSettingsContent(plugin)
  }

  // Special handling for seed-data plugin
  if (plugin.id === 'seed-data' || plugin.name === 'seed-data') {
    return `
      <div class="text-center py-8">
        <svg class="w-16 h-16 text-green-400 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253"/>
        </svg>
        <h3 class="text-lg font-medium text-gray-300 mb-2">Seed Data Generator</h3>
        <p class="text-gray-400 mb-6">Generate realistic example data for testing and development.</p>
        <a
          href="/admin/seed-data"
          class="inline-flex items-center gap-2 bg-green-600 hover:bg-green-700 text-white px-6 py-3 rounded-lg font-medium transition-colors"
        >
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
          </svg>
          Generate Seed Data
        </a>
      </div>
    `
  }

  return `
    <div class="text-center py-8">
      <svg class="w-12 h-12 text-gray-400 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
      </svg>
      <h3 class="text-lg font-medium text-gray-300 mb-2">No Settings Available</h3>
      <p class="text-gray-400">This plugin doesn't have any configurable settings.</p>
    </div>
  `
}

function renderActivityTab(activity: PluginActivity[]): string {
  return `
    <div class="backdrop-blur-md bg-black/20 rounded-xl border border-white/10 shadow-xl p-6">
      <h2 class="text-xl font-semibold text-white mb-4">Activity Log</h2>
      
      ${activity.length > 0 ? `
        <div class="space-y-4">
          ${activity.map(item => `
            <div class="flex items-start gap-3 p-3 rounded-lg bg-white/5">
              <div class="w-2 h-2 bg-blue-400 rounded-full mt-2"></div>
              <div class="flex-1">
                <div class="flex items-center justify-between">
                  <span class="text-sm font-medium text-white">${item.action}</span>
                  <span class="text-xs text-gray-400">${formatTimestamp(item.timestamp)}</span>
                </div>
                ${item.message ? `<p class="text-sm text-gray-300 mt-1">${item.message}</p>` : ''}
                ${item.user ? `<p class="text-xs text-gray-400 mt-1">by ${item.user}</p>` : ''}
              </div>
            </div>
          `).join('')}
        </div>
      ` : `
        <div class="text-center py-8">
          <svg class="w-12 h-12 text-gray-400 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
          </svg>
          <h3 class="text-lg font-medium text-gray-300 mb-2">No Activity</h3>
          <p class="text-gray-400">No recent activity for this plugin.</p>
        </div>
      `}
    </div>
  `
}

function renderInformationTab(plugin: any): string {
  return `
    ${plugin.description ? `
    <!-- About -->
    <div class="backdrop-blur-md bg-black/20 rounded-xl border border-white/10 shadow-xl p-6 mb-6">
      <h2 class="text-xl font-semibold text-white mb-3">About</h2>
      <p class="text-gray-300 leading-relaxed">${plugin.description}</p>
    </div>
    ` : ''}

    ${(plugin.settings?._routes?.length ?? 0) > 0 ? `
    <!-- Routes -->
    <div class="backdrop-blur-md bg-black/20 rounded-xl border border-white/10 shadow-xl p-6 mb-6">
      <h2 class="text-xl font-semibold text-white mb-4">Routes</h2>
      <div class="space-y-2">
        ${(plugin.settings._routes as Array<{ method: string; path: string; description?: string; requiresAuth?: boolean }>).map(r => {
          const badge = r.method === 'GET'
            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
            : r.method === 'POST'
            ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
            : r.method === 'DELETE'
            ? 'bg-red-500/20 text-red-300 border border-red-500/30'
            : 'bg-white/10 text-gray-300 border border-white/20'
          const pathHtml = r.method === 'GET'
            ? `<a href="${r.path}" class="font-mono text-sm text-blue-400 hover:text-blue-300 hover:underline">${r.path}</a>`
            : `<span class="font-mono text-sm text-gray-200">${r.path}</span>`
          const authBadge = r.requiresAuth
            ? `<span class="ml-2 text-xs text-amber-400/80">🔒 auth</span>`
            : ''
          return `
          <div class="flex items-start gap-3 py-2 border-b border-white/5 last:border-0">
            <span class="shrink-0 inline-block px-2 py-0.5 rounded text-xs font-bold ${badge}">${r.method}</span>
            <div class="min-w-0">
              <div class="flex items-center gap-1 flex-wrap">
                ${pathHtml}${authBadge}
              </div>
              ${r.description ? `<p class="text-xs text-gray-400 mt-0.5">${r.description}</p>` : ''}
            </div>
          </div>`
        }).join('')}
      </div>
    </div>
    ` : ''}

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <!-- Plugin Details -->
      <div class="backdrop-blur-md bg-black/20 rounded-xl border border-white/10 shadow-xl p-6">
        <h2 class="text-xl font-semibold text-white mb-4">Plugin Details</h2>
        <div class="space-y-3">
          <div class="flex justify-between">
            <span class="text-gray-400">Name:</span>
            <span class="text-white">${plugin.displayName}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-gray-400">Version:</span>
            <span class="text-white">${plugin.version}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-gray-400">Author:</span>
            <span class="text-white">${plugin.author}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-gray-400">Category:</span>
            <span class="text-white">${plugin.category}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-gray-400">Status:</span>
            <span class="text-white">${plugin.status}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-gray-400">Last Updated:</span>
            <span class="text-white">${plugin.lastUpdated}</span>
          </div>
        </div>
      </div>

      <!-- Dependencies & Permissions -->
      <div class="backdrop-blur-md bg-black/20 rounded-xl border border-white/10 shadow-xl p-6">
        <h2 class="text-xl font-semibold text-white mb-4">Dependencies & Permissions</h2>
        
        ${plugin.dependencies && plugin.dependencies.length > 0 ? `
          <div class="mb-6">
            <h3 class="text-sm font-medium text-gray-300 mb-2">Dependencies:</h3>
            <div class="space-y-1">
              ${plugin.dependencies.map((dep: string) => `
                <div class="inline-block bg-white/10 text-gray-300 text-sm px-2 py-1 rounded mr-2">${dep}</div>
              `).join('')}
            </div>
          </div>
        ` : ''}

        ${plugin.permissions && plugin.permissions.length > 0 ? `
          <div>
            <h3 class="text-sm font-medium text-gray-300 mb-2">Permissions:</h3>
            <div class="space-y-1">
              ${plugin.permissions.map((perm: string) => `
                <div class="inline-block bg-white/10 text-gray-300 text-sm px-2 py-1 rounded mr-2">${perm}</div>
              `).join('')}
            </div>
          </div>
        ` : ''}

        ${(!plugin.dependencies || plugin.dependencies.length === 0) && (!plugin.permissions || plugin.permissions.length === 0) ? `
          <p class="text-gray-400">No dependencies or special permissions required.</p>
        ` : ''}
      </div>
    </div>
  `
}

function formatTimestamp(timestamp: number): string {
  const date = new Date(timestamp * 1000)
  return date.toLocaleString()
}

// ==================== Plugin Settings Components ====================
// These render just the settings content, embedded within the shared layout

/**
 * Registry of custom plugin settings components
 * Plugins with custom settings UI register their render functions here
 */
type PluginSettingsRenderer = (plugin: any, settings: PluginSettings) => string

const pluginSettingsComponents: Record<string, PluginSettingsRenderer> = {
  'otp-login': renderOTPLoginSettingsContent,
  'email': renderEmailSettingsContent,
  'oauth-providers': renderOAuthProvidersSettingsContent,
}

/**
 * OTP Login plugin settings content
 */
function renderOTPLoginSettingsContent(plugin: any, settings: PluginSettings): string {
  const siteName = settings.siteName || 'SonicJS'
  const emailConfigured = settings._emailConfigured || false
  const codeLength = settings.codeLength || 6
  const codeExpiryMinutes = settings.codeExpiryMinutes || 10
  const maxAttempts = settings.maxAttempts || 3
  const rateLimitPerHour = settings.rateLimitPerHour || 5
  const allowNewUserRegistration = settings.allowNewUserRegistration || false
  const logoUrl = settings.logoUrl || ''
  const logoWidth = Number(settings.logoWidth) || 150
  const logoBorderWidth = Number(settings.logoBorderWidth) || 0
  const logoBorderColor = settings.logoBorderColor || '#ffffff'
  const loginUrl = settings.loginUrl || ''
  const loginButtonText = settings.loginButtonText || ''
  const previewButtonText = loginButtonText.trim() || `Sign in to ${siteName}`
  const previewLogoBorder = logoBorderWidth > 0 && logoBorderColor
    ? `border: ${logoBorderWidth}px solid ${escapeHtmlAttr(logoBorderColor)}; border-radius: 8px;`
    : ''

  return `
    <div class="space-y-6">
      <!-- Test OTP Section -->
      <div class="backdrop-blur-md bg-white/5 rounded-xl border border-white/10 p-6">
        <h3 class="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <span>📧</span> Test OTP Email
        </h3>

        ${!emailConfigured ? `
          <div class="bg-yellow-500/20 border border-yellow-500/30 rounded-lg p-4 mb-4">
            <p class="text-yellow-200 text-sm">
              <strong>⚠️ Email not configured.</strong>
              <a href="/admin/plugins/email" class="underline hover:text-yellow-100">Configure the Email plugin</a>
              to send real emails. Dev mode will show codes in the response.
            </p>
          </div>
        ` : `
          <div class="bg-green-500/20 border border-green-500/30 rounded-lg p-4 mb-4">
            <p class="text-green-200 text-sm">
              <strong>✅ Email configured.</strong> Test emails will be sent via Resend.
            </p>
          </div>
        `}

        <form id="testOtpForm" class="space-y-4">
          <div>
            <label for="testEmail" class="block text-sm font-medium text-gray-300 mb-2">
              Email Address
            </label>
            <input
              type="email"
              id="testEmail"
              name="email"
              placeholder="Enter your email to receive a test code"
              class="w-full px-4 py-3 rounded-lg bg-white/5 border border-white/10 focus:border-blue-500 focus:outline-none text-white placeholder-zinc-500"
              required
            />
          </div>

          <button
            type="submit"
            id="sendTestBtn"
            class="w-full px-6 py-3 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-lg font-medium hover:from-blue-600 hover:to-purple-700 transition-all flex items-center justify-center gap-2"
          >
            <span id="sendBtnText">Send Test Code</span>
            <span id="sendBtnSpinner" class="hidden">
              <svg class="animate-spin h-5 w-5" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
              </svg>
            </span>
          </button>
        </form>

        <div id="testResult" class="hidden mt-4 rounded-lg p-4"></div>

        <!-- Verify Code Section -->
        <div id="verifySection" class="hidden mt-6 pt-6 border-t border-white/10">
          <h4 class="text-md font-semibold text-white mb-3">Verify Code</h4>
          <form id="verifyForm" class="space-y-4">
            <div>
              <label for="otpCode" class="block text-sm font-medium text-gray-300 mb-2">
                Enter the code you received
              </label>
              <input
                type="text"
                id="otpCode"
                name="code"
                placeholder="000000"
                maxlength="8"
                class="w-full px-4 py-3 rounded-lg bg-white/5 border border-white/10 focus:border-blue-500 focus:outline-none text-white text-center text-2xl tracking-widest font-mono"
                required
              />
            </div>
            <button
              type="submit"
              class="w-full px-6 py-3 bg-green-600 hover:bg-green-700 text-white rounded-lg font-medium transition-all"
            >
              Verify Code
            </button>
          </form>
          <div id="verifyResult" class="hidden mt-4 rounded-lg p-4"></div>
        </div>
      </div>

      <!-- Configuration Section -->
      <div class="backdrop-blur-md bg-white/5 rounded-xl border border-white/10 p-6">
        <h3 class="text-lg font-semibold text-white mb-4">Code Settings</h3>

        <form id="settings-form" class="space-y-4">
          <div>
            <label for="setting_logoUrl" class="block text-sm font-medium text-gray-300 mb-2">
              Logo URL
            </label>
            <input
              type="url"
              id="setting_logoUrl"
              name="setting_logoUrl"
              value="${escapeHtmlAttr(logoUrl)}"
              placeholder="https://yourdomain.com/logo.png"
              class="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 focus:border-blue-500 focus:outline-none text-white"
            />
            <p class="text-xs text-gray-500 mt-1">Optional. Displayed at the top of the OTP email.</p>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label for="setting_logoWidth" class="block text-sm font-medium text-gray-300 mb-2">
                Logo Width (px)
              </label>
              <input
                type="number"
                id="setting_logoWidth"
                name="setting_logoWidth"
                min="20"
                max="600"
                value="${logoWidth}"
                class="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 focus:border-blue-500 focus:outline-none text-white"
              />
              <p class="text-xs text-gray-500 mt-1">Max width of the logo (20-600).</p>
            </div>

            <div>
              <label for="setting_logoBorderWidth" class="block text-sm font-medium text-gray-300 mb-2">
                Border Thickness (px)
              </label>
              <input
                type="number"
                id="setting_logoBorderWidth"
                name="setting_logoBorderWidth"
                min="0"
                max="20"
                value="${logoBorderWidth}"
                class="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 focus:border-blue-500 focus:outline-none text-white"
              />
              <p class="text-xs text-gray-500 mt-1">0 disables the border.</p>
            </div>

            <div>
              <label for="setting_logoBorderColor" class="block text-sm font-medium text-gray-300 mb-2">
                Border Color
              </label>
              <div class="flex gap-2">
                <input
                  type="color"
                  id="setting_logoBorderColor_picker"
                  value="${escapeHtmlAttr(/^#[0-9a-fA-F]{6}$/.test(logoBorderColor) ? logoBorderColor : '#ffffff')}"
                  oninput="document.getElementById('setting_logoBorderColor').value = this.value"
                  class="w-12 h-10 rounded-lg bg-white/5 border border-white/10 cursor-pointer"
                />
                <input
                  type="text"
                  id="setting_logoBorderColor"
                  name="setting_logoBorderColor"
                  value="${escapeHtmlAttr(logoBorderColor)}"
                  placeholder="#ffffff"
                  class="flex-1 px-3 py-2 rounded-lg bg-white/5 border border-white/10 focus:border-blue-500 focus:outline-none text-white"
                />
              </div>
              <p class="text-xs text-gray-500 mt-1">Hex, rgb(), or named color.</p>
            </div>
          </div>

          <div>
            <label for="setting_loginUrl" class="block text-sm font-medium text-gray-300 mb-2">
              Login URL
            </label>
            <input
              type="url"
              id="setting_loginUrl"
              name="setting_loginUrl"
              value="${escapeHtmlAttr(loginUrl)}"
              placeholder="https://yourdomain.com/login"
              class="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 focus:border-blue-500 focus:outline-none text-white"
            />
            <p class="text-xs text-gray-500 mt-1">Optional. If set, a "Sign in" button is added to the email.</p>
          </div>

          <div>
            <label for="setting_loginButtonText" class="block text-sm font-medium text-gray-300 mb-2">
              Login Button Text
            </label>
            <input
              type="text"
              id="setting_loginButtonText"
              name="setting_loginButtonText"
              value="${escapeHtmlAttr(loginButtonText)}"
              placeholder="Sign in to ${escapeHtmlAttr(siteName)}"
              class="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 focus:border-blue-500 focus:outline-none text-white"
            />
            <p class="text-xs text-gray-500 mt-1">Optional. Defaults to "Sign in to ${siteName}".</p>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label for="setting_codeLength" class="block text-sm font-medium text-gray-300 mb-2">
                Code Length
              </label>
              <input
                type="number"
                id="setting_codeLength"
                name="setting_codeLength"
                min="4"
                max="8"
                value="${codeLength}"
                class="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 focus:border-blue-500 focus:outline-none text-white"
              />
              <p class="text-xs text-gray-500 mt-1">Number of digits (4-8)</p>
            </div>

            <div>
              <label for="setting_codeExpiryMinutes" class="block text-sm font-medium text-gray-300 mb-2">
                Code Expiry (minutes)
              </label>
              <input
                type="number"
                id="setting_codeExpiryMinutes"
                name="setting_codeExpiryMinutes"
                min="5"
                max="60"
                value="${codeExpiryMinutes}"
                class="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 focus:border-blue-500 focus:outline-none text-white"
              />
              <p class="text-xs text-gray-500 mt-1">How long codes remain valid</p>
            </div>

            <div>
              <label for="setting_maxAttempts" class="block text-sm font-medium text-gray-300 mb-2">
                Maximum Attempts
              </label>
              <input
                type="number"
                id="setting_maxAttempts"
                name="setting_maxAttempts"
                min="3"
                max="10"
                value="${maxAttempts}"
                class="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 focus:border-blue-500 focus:outline-none text-white"
              />
              <p class="text-xs text-gray-500 mt-1">Max verification attempts</p>
            </div>

            <div>
              <label for="setting_rateLimitPerHour" class="block text-sm font-medium text-gray-300 mb-2">
                Rate Limit (per hour)
              </label>
              <input
                type="number"
                id="setting_rateLimitPerHour"
                name="setting_rateLimitPerHour"
                min="3"
                max="20"
                value="${rateLimitPerHour}"
                class="w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 focus:border-blue-500 focus:outline-none text-white"
              />
              <p class="text-xs text-gray-500 mt-1">Max requests per email per hour</p>
            </div>
          </div>

          <div class="flex items-center pt-2">
            <input
              type="checkbox"
              id="setting_allowNewUserRegistration"
              name="setting_allowNewUserRegistration"
              ${allowNewUserRegistration ? 'checked' : ''}
              class="w-4 h-4 rounded border-white/10"
            />
            <label for="setting_allowNewUserRegistration" class="ml-2 text-sm text-gray-300">
              Allow new user registration via OTP
            </label>
          </div>
        </form>
      </div>

      <!-- Email Preview Section -->
      <div class="backdrop-blur-md bg-white/5 rounded-xl border border-white/10 p-6">
        <h3 class="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <span>👁️</span> Email Preview
        </h3>
        <p class="text-gray-400 text-sm mb-4">
          This is how the OTP email will appear to users. The site name "<strong class="text-white">${siteName}</strong>" is configured in
          <a href="/admin/settings/general" class="text-blue-400 hover:text-blue-300 underline">General Settings</a>.
        </p>

        <div class="bg-white rounded-lg overflow-hidden shadow-lg">
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px 20px; text-align: center;">
            ${logoUrl ? `<img src="${escapeHtmlAttr(logoUrl)}" alt="Logo" style="max-width: ${logoWidth}px; width: 100%; height: auto; margin: 0 auto 16px; ${previewLogoBorder}">` : ''}
            <h3 style="margin: 0 0 8px 0; font-size: 24px; font-weight: 600;">Your Login Code</h3>
            <p style="margin: 0; opacity: 0.95; font-size: 14px;">Enter this code to sign in to ${siteName}</p>
          </div>

          <div style="padding: 30px 20px;">
            <div style="background: #f8f9fa; border: 2px dashed #667eea; border-radius: 12px; padding: 20px; text-align: center; margin: 0 0 20px 0;">
              <div style="font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #667eea; font-family: monospace;">
                123456
              </div>
            </div>

            ${loginUrl ? `
            <div style="text-align: center; margin: 0 0 20px 0;">
              <a href="${escapeHtmlAttr(loginUrl)}" style="display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; padding: 12px 28px; border-radius: 6px; font-weight: 600; font-size: 14px;">
                ${escapeHtmlAttr(previewButtonText)}
              </a>
            </div>
            ` : ''}

            <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 12px 16px; margin: 0 0 20px 0; border-radius: 4px;">
              <p style="margin: 0; font-size: 13px; color: #856404;">
                <strong>⚠️ This code expires in ${codeExpiryMinutes} minutes</strong>
              </p>
            </div>

            <div style="background: #e8f4ff; border-radius: 8px; padding: 16px; margin: 0;">
              <p style="margin: 0 0 8px 0; font-size: 13px; color: #0066cc; font-weight: 600;">
                🔒 Security Notice
              </p>
              <p style="margin: 0; font-size: 12px; color: #004080; line-height: 1.5;">
                Never share this code with anyone. ${siteName} will never ask you for this code via phone, email, or social media.
              </p>
            </div>
          </div>
        </div>
      </div>

      <!-- Features -->
      <div class="backdrop-blur-md bg-blue-500/10 border border-blue-500/20 rounded-xl p-6">
        <h3 class="font-semibold text-blue-400 mb-3">🔢 Features</h3>
        <ul class="text-sm text-blue-200 space-y-2">
          <li>✓ Passwordless authentication</li>
          <li>✓ Secure random code generation</li>
          <li>✓ Rate limiting protection</li>
          <li>✓ Brute force prevention</li>
          <li>✓ Mobile-friendly UX</li>
        </ul>
      </div>

      <!-- Quick Links -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <a href="/admin/plugins/email" class="backdrop-blur-md bg-white/5 border border-white/10 rounded-xl p-4 hover:bg-white/10 transition-all flex items-center gap-3">
          <span class="text-2xl">📬</span>
          <div>
            <div class="font-medium text-white">Email Settings</div>
            <div class="text-sm text-zinc-400">Configure Resend API</div>
          </div>
        </a>
        <a href="/admin/settings/general" class="backdrop-blur-md bg-white/5 border border-white/10 rounded-xl p-4 hover:bg-white/10 transition-all flex items-center gap-3">
          <span class="text-2xl">🏷️</span>
          <div>
            <div class="font-medium text-white">Site Name</div>
            <div class="text-sm text-zinc-400">Change "${siteName}"</div>
          </div>
        </a>
      </div>
    </div>

    <script>
      let testEmail = '';

      document.getElementById('testOtpForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = document.getElementById('testEmail').value;
        testEmail = email;
        const btn = document.getElementById('sendTestBtn');
        const btnText = document.getElementById('sendBtnText');
        const spinner = document.getElementById('sendBtnSpinner');
        const result = document.getElementById('testResult');
        const verifySection = document.getElementById('verifySection');

        btn.disabled = true;
        btnText.textContent = 'Sending...';
        spinner.classList.remove('hidden');
        result.classList.add('hidden');

        try {
          const response = await fetch('/auth/otp/request', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
          });

          const data = await response.json();

          if (response.ok) {
            result.className = 'mt-4 rounded-lg p-4 bg-green-500/20 border border-green-500/30';
            let html = '<p class="text-green-200"><strong>✅ Code sent!</strong> Check your inbox.</p>';
            if (data.dev_code) {
              html += '<p class="text-green-300 mt-2 font-mono text-lg">Dev code: <strong>' + data.dev_code + '</strong></p>';
            }
            result.innerHTML = html;
            verifySection.classList.remove('hidden');
          } else {
            throw new Error(data.error || 'Failed to send code');
          }
        } catch (error) {
          result.className = 'mt-4 rounded-lg p-4 bg-red-500/20 border border-red-500/30';
          result.innerHTML = '<p class="text-red-200"><strong>❌ Error:</strong> ' + error.message + '</p>';
        } finally {
          btn.disabled = false;
          btnText.textContent = 'Send Test Code';
          spinner.classList.add('hidden');
          result.classList.remove('hidden');
        }
      });

      document.getElementById('verifyForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const code = document.getElementById('otpCode').value;
        const result = document.getElementById('verifyResult');

        try {
          const response = await fetch('/auth/otp/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: testEmail, code })
          });

          const data = await response.json();

          if (response.ok && data.success) {
            result.className = 'mt-4 rounded-lg p-4 bg-green-500/20 border border-green-500/30';
            result.innerHTML = '<p class="text-green-200"><strong>✅ Verification successful!</strong> The OTP flow is working correctly.</p>';
          } else {
            throw new Error(data.error || 'Verification failed');
          }
        } catch (error) {
          result.className = 'mt-4 rounded-lg p-4 bg-red-500/20 border border-red-500/30';
          result.innerHTML = '<p class="text-red-200"><strong>❌ Error:</strong> ' + error.message + '</p>';
        } finally {
          result.classList.remove('hidden');
        }
      });
    </script>
  `
}

/**
 * Email plugin settings content
 */
function renderEmailSettingsContent(_plugin: any, settings: PluginSettings): string {
  const provider = (settings.provider as string) || 'cloudflare'
  const resendApiKey = settings.resendApiKey || ''
  const fromEmail = settings.fromEmail || ''
  const fromName = settings.fromName || ''
  const replyTo = settings.replyTo || ''
  const logoUrl = settings.logoUrl || ''
  const cfAccountId = settings.cfAccountId || ''
  const cfEmailApiToken = settings.cfEmailApiToken || ''

  const inputClass = 'w-full px-3 py-2 rounded-lg bg-white/5 border border-white/10 focus:border-blue-500 focus:outline-none text-white'
  const selectClass = 'w-full px-3 py-2 rounded-lg bg-zinc-800 border border-white/10 focus:border-blue-500 focus:outline-none text-white [&>option]:bg-zinc-800'
  const hintClass = 'text-xs text-gray-500 mt-1'
  const envNote = (varName: string) =>
    `<p class="${hintClass} text-amber-400/80">⚡ <code>${varName}</code> env var overrides this field when set.</p>`

  return `
    <div class="space-y-6">
      <!-- Provider + Settings Form -->
      <div class="backdrop-blur-md bg-white/5 rounded-xl border border-white/10 p-6">
        <h3 class="text-lg font-semibold text-white mb-4">Email Configuration</h3>

        <form id="settings-form" class="space-y-5">

          <!-- Provider selector -->
          <div>
            <label for="setting_provider" class="block text-sm font-medium text-gray-300 mb-2">
              Email Provider <span class="text-red-500">*</span>
            </label>
            <select id="setting_provider" name="setting_provider" class="${selectClass}">
              <option value="cloudflare" ${provider === 'cloudflare' ? 'selected' : ''}>Cloudflare Email Service</option>
              <option value="resend" ${provider === 'resend' ? 'selected' : ''}>Resend</option>
            </select>
            ${envNote('RESEND_API_KEY')}
          </div>

          <!-- Resend fields (visible when provider=resend) -->
          <div id="resend-fields" class="space-y-4" style="${provider !== 'resend' ? 'display:none' : ''}">
            <div>
              <label for="setting_resendApiKey" class="block text-sm font-medium text-gray-300 mb-2">
                Resend API Key <span class="text-red-500">*</span>
              </label>
              <input type="password" id="setting_resendApiKey" name="setting_resendApiKey"
                value="${escapeHtmlAttr(resendApiKey)}" placeholder="re_..." class="${inputClass}" />
              ${envNote('RESEND_API_KEY')}
              <p class="${hintClass}">Get your key at resend.com/api-keys</p>
            </div>
          </div>

          <!-- CF Email fields (visible when provider=cloudflare) -->
          <div id="cf-fields" class="space-y-4" style="${provider !== 'cloudflare' ? 'display:none' : ''}">
            <div class="bg-blue-500/10 border border-blue-500/20 rounded-lg p-3 text-sm text-blue-200">
              Requires a <code>send_email</code> binding named <code>EMAIL</code> in your <code>wrangler.toml</code>.
              No API key needed — auth is via the binding.
            </div>
            <div>
              <label for="setting_cfAccountId" class="block text-sm font-medium text-gray-300 mb-2">CF Account ID</label>
              <input type="text" id="setting_cfAccountId" name="setting_cfAccountId"
                value="${escapeHtmlAttr(cfAccountId)}" placeholder="f61c658f..." class="${inputClass}" />
              ${envNote('CF_ACCOUNT_ID')}
              <p class="${hintClass}">Used by the delivery-sync cron. Found in Cloudflare dashboard sidebar.</p>
            </div>
            <div>
              <label for="setting_cfEmailApiToken" class="block text-sm font-medium text-gray-300 mb-2">CF Email API Token</label>
              <input type="password" id="setting_cfEmailApiToken" name="setting_cfEmailApiToken"
                value="${escapeHtmlAttr(cfEmailApiToken)}" placeholder="••••••••" class="${inputClass}" />
              ${envNote('EMAIL_API_TOKEN')}
              <p class="${hintClass}">API token with Email Routing read permission.</p>
            </div>
          </div>

          <!-- Common fields -->
          <div>
            <label for="setting_fromEmail" class="block text-sm font-medium text-gray-300 mb-2">
              From Email <span class="text-red-500">*</span>
            </label>
            <input type="email" id="setting_fromEmail" name="setting_fromEmail"
              value="${escapeHtmlAttr(fromEmail)}" placeholder="noreply@yourdomain.com" class="${inputClass}" required />
          </div>

          <div>
            <label for="setting_fromName" class="block text-sm font-medium text-gray-300 mb-2">
              From Name <span class="text-red-500">*</span>
            </label>
            <input type="text" id="setting_fromName" name="setting_fromName"
              value="${escapeHtmlAttr(fromName)}" placeholder="Your App Name" class="${inputClass}" required />
          </div>

          <div>
            <label for="setting_replyTo" class="block text-sm font-medium text-gray-300 mb-2">Reply-To Email</label>
            <input type="email" id="setting_replyTo" name="setting_replyTo"
              value="${escapeHtmlAttr(replyTo)}" placeholder="support@yourdomain.com" class="${inputClass}" />
          </div>

          <div>
            <label for="setting_logoUrl" class="block text-sm font-medium text-gray-300 mb-2">Logo URL</label>
            <input type="url" id="setting_logoUrl" name="setting_logoUrl"
              value="${escapeHtmlAttr(logoUrl)}" placeholder="https://yourdomain.com/logo.png" class="${inputClass}" />
            <p class="${hintClass}">Logo shown in email templates.</p>
          </div>

        </form>
      </div>

      <!-- Test Email Section -->
      <div class="backdrop-blur-md bg-white/5 rounded-xl border border-white/10 p-6">
        <h3 class="text-lg font-semibold text-white mb-4">Send Test Email</h3>
        <div class="flex gap-3">
          <input type="email" id="testEmailAddress" placeholder="Enter email address"
            class="flex-1 px-3 py-2 rounded-lg bg-white/5 border border-white/10 focus:border-blue-500 focus:outline-none text-white" />
          <button type="button" id="testEmailBtn"
            class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-all">
            Send Test
          </button>
        </div>
        <div id="testEmailResult" class="hidden mt-4 rounded-lg p-4"></div>
      </div>

      <!-- Templates info -->
      <div class="backdrop-blur-md bg-blue-500/10 border border-blue-500/20 rounded-xl p-6">
        <h3 class="font-semibold text-blue-400 mb-3">📧 Email Templates Included</h3>
        <ul class="text-sm text-blue-200 space-y-2">
          <li>✓ Welcome / registration confirmation</li>
          <li>✓ Email verification</li>
          <li>✓ Password reset</li>
          <li>✓ One-time code (2FA)</li>
          <li>✓ Invitation</li>
        </ul>
        <p class="text-xs text-blue-300 mt-4">
          Templates are code-based — customize by editing the plugin files.
        </p>
      </div>
    </div>

    <script>
      (function () {
        const providerSel = document.getElementById('setting_provider');
        const resendFields = document.getElementById('resend-fields');
        const cfFields = document.getElementById('cf-fields');

        function updateVisibility() {
          const v = providerSel.value;
          resendFields.style.display = v === 'resend' ? '' : 'none';
          cfFields.style.display = v === 'cloudflare' ? '' : 'none';
        }

        providerSel.addEventListener('change', updateVisibility);

        document.getElementById('testEmailBtn').addEventListener('click', async () => {
          const email = document.getElementById('testEmailAddress').value;
          if (!email) { alert('Please enter an email address'); return; }

          const resultEl = document.getElementById('testEmailResult');
          resultEl.className = 'mt-4 rounded-lg p-4 bg-blue-500/20 border border-blue-500/30';
          resultEl.innerHTML = '📧 Sending test email...';
          resultEl.classList.remove('hidden');

          try {
            const response = await fetch('/admin/email/test', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ to: email })
            });
            const data = await response.json();
            if (response.ok && data.success && !data.warning) {
              resultEl.className = 'mt-4 rounded-lg p-4 bg-green-500/20 border border-green-500/30';
              resultEl.innerHTML = '<p class="text-green-200">✅ Test email sent via <strong>' + data.provider + '</strong>. Check your inbox.</p>';
            } else if (response.ok && data.warning) {
              resultEl.className = 'mt-4 rounded-lg p-4 bg-yellow-500/20 border border-yellow-500/30';
              resultEl.innerHTML = '<p class="text-yellow-200">⚠️ ' + data.warning + '</p>';
            } else {
              resultEl.className = 'mt-4 rounded-lg p-4 bg-red-500/20 border border-red-500/30';
              const errMsg = data.error || data.result?.error || 'Failed to send test email.';
              resultEl.innerHTML = '<p class="text-red-200">❌ ' + errMsg + '</p>';
            }
          } catch {
            resultEl.className = 'mt-4 rounded-lg p-4 bg-red-500/20 border border-red-500/30';
            resultEl.innerHTML = '<p class="text-red-200">❌ Network error. Please try again.</p>';
          }
        });
      })();
    </script>
  `
}

/**
 * User Profiles plugin settings content.
 *
 * Profile fields are a CODE-DEFINED data model (declared via defineUserProfile()
 * in the app entry point) — not editable through the admin UI. This page explains
 * where to define them and shows the current configured state.
 */
function renderUserProfilesSettingsContent(plugin: any): string {
  const config = plugin.profileConfig as PluginSettingsPageData['plugin']['profileConfig']
  const fields = config?.fields ?? []
  const registrationFields = config?.registrationFields ?? []
  const isConfigured = fields.length > 0

  const codeExample = `import { defineUserProfile } from '@sonicjs-cms/core'

defineUserProfile({
  fields: [
    { name: 'bio', label: 'Bio', type: 'textarea' },
    { name: 'company', label: 'Company', type: 'text' },
    { name: 'jobTitle', label: 'Job Title', type: 'text' },
  ],
  // Field names shown on the "Create User" form (optional):
  registrationFields: ['company'],
})`

  const statusBanner = isConfigured
    ? `
      <div class="bg-green-500/20 border border-green-500/30 rounded-lg p-4">
        <p class="text-green-200 text-sm">
          <strong>✅ Profile fields configured.</strong>
          ${fields.length} field${fields.length !== 1 ? 's' : ''} defined — the
          <span class="font-medium">Profile Information</span> section now appears on the user create/edit pages.
        </p>
      </div>`
    : `
      <div class="bg-yellow-500/20 border border-yellow-500/30 rounded-lg p-4">
        <p class="text-yellow-200 text-sm">
          <strong>⚠️ No profile fields defined yet.</strong>
          The <span class="font-medium">Profile Information</span> section stays hidden on the user
          create/edit pages until you declare fields in code with <code>defineUserProfile()</code>.
        </p>
      </div>`

  const fieldsTable = isConfigured
    ? `
      <div class="backdrop-blur-md bg-white/5 rounded-xl border border-white/10 p-6">
        <h3 class="text-lg font-semibold text-white mb-4">Configured Fields</h3>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm">
            <thead>
              <tr class="text-gray-400 border-b border-white/10">
                <th class="py-2 pr-4 font-medium">Name</th>
                <th class="py-2 pr-4 font-medium">Label</th>
                <th class="py-2 pr-4 font-medium">Type</th>
                <th class="py-2 pr-4 font-medium">Required</th>
                <th class="py-2 font-medium">On signup</th>
              </tr>
            </thead>
            <tbody>
              ${fields.map(f => `
                <tr class="border-b border-white/5 text-gray-200">
                  <td class="py-2 pr-4 font-mono text-xs">${escapeHtmlAttr(f.name)}</td>
                  <td class="py-2 pr-4">${escapeHtmlAttr(f.label)}</td>
                  <td class="py-2 pr-4 font-mono text-xs">${escapeHtmlAttr(f.type)}</td>
                  <td class="py-2 pr-4">${f.required ? 'Yes' : 'No'}</td>
                  <td class="py-2">${registrationFields.includes(f.name) ? 'Yes' : 'No'}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>`
    : ''

  return `
    <div class="space-y-6">
      ${statusBanner}

      <!-- Where to edit -->
      <div class="backdrop-blur-md bg-white/5 rounded-xl border border-white/10 p-6">
        <h3 class="text-lg font-semibold text-white mb-2 flex items-center gap-2">
          <span>🧩</span> Define profile fields in code
        </h3>
        <p class="text-gray-300 text-sm mb-4">
          User profile fields are part of your application's data model, so they live in code — not in this admin UI.
          Add or change fields by calling <code class="text-blue-300">defineUserProfile()</code> in your app entry point,
          then redeploy.
        </p>
        <div class="bg-black/40 border border-white/10 rounded-lg p-3 mb-4">
          <p class="text-xs text-gray-400 mb-1">Edit this file:</p>
          <code class="text-sm text-blue-300 font-mono">my-sonicjs-app/src/index.ts</code>
        </div>
        <p class="text-xs text-gray-400 mb-2">Example — add this near your <code>registerCollections([...])</code> call:</p>
        <pre class="bg-black/60 border border-white/10 rounded-lg p-4 overflow-x-auto"><code class="text-sm text-gray-200 font-mono whitespace-pre">${escapeHtmlAttr(codeExample)}</code></pre>
        <p class="text-xs text-gray-400 mt-4">
          Supported field types: <code>text</code>, <code>textarea</code>, <code>number</code>, <code>boolean</code>,
          <code>select</code>, <code>date</code>. Use <code>options</code> for <code>select</code> and
          <code>required</code> / <code>validation</code> to enforce input rules.
        </p>
      </div>

      ${fieldsTable}
    </div>
  `
}

/**
 * OAuth Providers plugin settings — renders GitHub and Google credential fields.
 * Settings are stored as { providers: { github: {...}, google: {...} } }.
 * The saveSettings() JS function handles the nested structure for oauth-providers.
 */
function renderOAuthProvidersSettingsContent(plugin: any, settings: PluginSettings): string {
  const providers = (settings.providers as Record<string, any>) || {}
  const gh = providers.github || {}
  const gg = providers.google || {}
  const inputClass = 'backdrop-blur-sm bg-white/10 border border-white/20 rounded-lg px-3 py-2 text-white placeholder-gray-300 focus:border-blue-400 focus:outline-none transition-colors w-full'

  return `
    <div class="space-y-6">
      <form id="settings-form">
        <div class="backdrop-blur-md bg-white/5 rounded-xl border border-white/10 p-6 space-y-6">
          <h3 class="text-lg font-semibold text-white">GitHub OAuth</h3>
          <div>
            <label for="oauth_github_clientId" class="block text-sm font-medium text-gray-300 mb-2">Client ID</label>
            <input type="text" id="oauth_github_clientId" name="oauth_github_clientId"
              value="${escapeHtmlAttr(gh.clientId || '')}"
              placeholder="GitHub OAuth App Client ID" class="${inputClass}" />
          </div>
          <div>
            <label for="oauth_github_clientSecret" class="block text-sm font-medium text-gray-300 mb-2">Client Secret</label>
            <input type="password" id="oauth_github_clientSecret" name="oauth_github_clientSecret"
              value="${escapeHtmlAttr(gh.clientSecret || '')}"
              placeholder="GitHub OAuth App Client Secret" class="${inputClass}" />
          </div>
          <div class="flex items-center gap-3">
            <input type="checkbox" id="oauth_github_enabled" name="oauth_github_enabled"
              ${gh.enabled ? 'checked' : ''} class="w-4 h-4 rounded border-white/10" />
            <label for="oauth_github_enabled" class="text-sm text-gray-300">Enable GitHub login</label>
          </div>
        </div>

        <div class="backdrop-blur-md bg-white/5 rounded-xl border border-white/10 p-6 space-y-6 mt-6">
          <h3 class="text-lg font-semibold text-white">Google OAuth</h3>
          <div>
            <label for="oauth_google_clientId" class="block text-sm font-medium text-gray-300 mb-2">Client ID</label>
            <input type="text" id="oauth_google_clientId" name="oauth_google_clientId"
              value="${escapeHtmlAttr(gg.clientId || '')}"
              placeholder="Google OAuth Client ID" class="${inputClass}" />
          </div>
          <div>
            <label for="oauth_google_clientSecret" class="block text-sm font-medium text-gray-300 mb-2">Client Secret</label>
            <input type="password" id="oauth_google_clientSecret" name="oauth_google_clientSecret"
              value="${escapeHtmlAttr(gg.clientSecret || '')}"
              placeholder="Google OAuth Client Secret" class="${inputClass}" />
          </div>
          <div class="flex items-center gap-3">
            <input type="checkbox" id="oauth_google_enabled" name="oauth_google_enabled"
              ${gg.enabled ? 'checked' : ''} class="w-4 h-4 rounded border-white/10" />
            <label for="oauth_google_enabled" class="text-sm text-gray-300">Enable Google login</label>
          </div>
        </div>
      </form>
    </div>
  `
}

/**
 * Check if a plugin has a custom settings component
 */
export function hasCustomSettingsComponent(pluginId: string): boolean {
  return pluginId in pluginSettingsComponents
}

/**
 * Get the custom settings component for a plugin
 */
export function getCustomSettingsComponent(pluginId: string): PluginSettingsRenderer | undefined {
  return pluginSettingsComponents[pluginId]
}