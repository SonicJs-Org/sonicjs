/**
 * Example Plugin — Admin Routes
 *
 * Renders inside the shared admin layout (sidebar, nav, header) by calling
 * renderAdminLayoutCatalyst from @sonicjs-cms/core. This is the DEFAULT
 * pattern for plugin admin pages — provide inner `content` HTML only;
 * the layout owns <html>, <head>, <body>, sidebar, and nav chrome.
 *
 * Pattern (copy this for your own plugin):
 *   1. requireAuth() is applied by the core framework before this route fires.
 *   2. Pull user + pluginMenuItems from context.
 *   3. Build a `content` string — just the page body, no outer chrome.
 *   4. Call renderAdminLayoutCatalyst(layoutData) and return c.html(result).
 *
 * Gear icon:
 *   Every plugin admin page should include a gear icon linking to
 *   /admin/plugins/<id>#settings. Admins can then jump straight to the
 *   settings form without navigating through the Plugins list.
 *
 * Escape hatch:
 *   If you need a fully custom page (OAuth callback, print view, embedded
 *   widget), return c.html(<full HTML document>) without calling
 *   renderAdminLayoutCatalyst. That still works — it just bypasses the
 *   shared chrome.
 */

import { Hono } from 'hono'
import { renderAdminLayoutCatalyst, escapeHtml } from '@sonicjs-cms/core'
import type { AdminLayoutCatalystData } from '@sonicjs-cms/core'

export function createExampleAdminRoutes(options: { greeting?: string; defaultName?: string } = {}): Hono {
  const router = new Hono<any>()

  router.get('/', (c) => {
    const greeting = options.greeting ?? 'Hello, Cruel World!'
    const defaultName = options.defaultName ?? 'Stranger'
    const user = c.get('user') as { email: string; role: string } | undefined
    const dynamicMenuItems = c.get('pluginMenuItems') as Array<{ label: string; path: string; icon: string }> | undefined

    const content = `
      <div class="w-full px-4 sm:px-6 lg:px-8 py-6">

        <div class="flex items-center justify-between mb-6">
          <div>
            <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">Example Plugin</h1>
            <p class="mt-1 text-sm/6 text-zinc-500 dark:text-zinc-400">
              A demo plugin for understanding the SonicJS v3 plugin system.
            </p>
          </div>
          <a
            href="/admin/plugins/example#settings"
            title="Plugin settings"
            class="inline-flex items-center gap-2 rounded-lg bg-zinc-100 dark:bg-zinc-800 px-3 py-2 text-sm font-medium text-zinc-700 dark:text-zinc-300 hover:bg-zinc-200 dark:hover:bg-zinc-700 transition-colors"
          >
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
            </svg>
            Settings
          </a>
        </div>

        <div class="backdrop-blur-md bg-black/20 rounded-xl border border-white/10 shadow-xl p-6 mb-6">
          <h2 class="text-lg font-semibold text-white mb-3">Current Config</h2>
          <dl class="space-y-2 text-sm">
            <div class="flex items-center gap-3">
              <dt class="text-gray-400 w-28 shrink-0">Greeting</dt>
              <dd class="text-green-400 font-mono">${escapeHtml(greeting)}</dd>
            </div>
            <div class="flex items-center gap-3">
              <dt class="text-gray-400 w-28 shrink-0">Default name</dt>
              <dd class="text-green-400 font-mono">${escapeHtml(defaultName)}</dd>
            </div>
          </dl>
          <p class="text-xs text-gray-500 mt-3">
            Try: <a href="/example" class="text-blue-400 hover:text-blue-300 font-mono">/example</a>
            → greets <span class="text-green-400 font-mono">${escapeHtml(defaultName)}</span>
          </p>
        </div>

        <!-- Moods Collection ─────────────────────────────────────────────────
             Shows how a plugin contributes a collection to the document repo.
             The core /admin/content/:collection route provides full CRUD for free —
             the plugin just links to it. -->
        <div class="backdrop-blur-md bg-black/20 rounded-xl border border-white/10 shadow-xl p-6 mb-6">
          <div class="flex items-center justify-between mb-4">
            <div>
              <h2 class="text-lg font-semibold text-white">😈 Moods</h2>
              <p class="text-xs text-gray-400 mt-0.5">
                A random published mood is included in every API response.
                Add, edit, or remove moods below.
              </p>
            </div>
            <a
              href="/admin/content?model=example&page=1"
              class="inline-flex items-center gap-1.5 rounded-lg bg-gradient-to-r from-cyan-500 to-purple-600 hover:from-cyan-400 hover:to-purple-500 px-3 py-2 text-sm font-semibold text-white shadow-sm transition-all duration-200"
            >
              <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/>
              </svg>
              Manage Moods
            </a>
          </div>
          <p class="text-xs text-gray-500">
            Try: <a href="/example" class="text-blue-400 hover:text-blue-300 font-mono">/example</a>
            → response includes a random <code class="text-purple-400">mood</code> field from this collection.
          </p>
        </div>

        <div class="backdrop-blur-md bg-black/20 rounded-xl border border-white/10 shadow-xl p-6 mb-6">
          <h2 class="text-lg font-semibold text-white mb-3">How This Plugin Works</h2>
          <dl class="space-y-3 text-sm">
            <div>
              <dt class="text-gray-400 font-medium">Public API</dt>
              <dd><a href="/example" class="text-blue-400 hover:text-blue-300 font-mono">GET /example</a></dd>
              <dd><a href="/example/traveller" class="text-blue-400 hover:text-blue-300 font-mono">GET /example/traveller</a></dd>
              <dd class="text-gray-500 text-xs mt-1">Routes at /example/* not /api/* — user plugins mount after the core /:collection catch-all.</dd>
            </div>
            <div>
              <dt class="text-gray-400 font-medium">Admin page</dt>
              <dd class="text-gray-200 font-mono">GET /admin/example</dd>
            </div>
            <div>
              <dt class="text-gray-400 font-medium">Hook subscriptions</dt>
              <dd class="text-gray-200 font-mono">content:after:create</dd>
              <dd class="text-gray-200 font-mono">auth:registration:completed</dd>
            </div>
            <div>
              <dt class="text-gray-400 font-medium">Settings</dt>
              <dd><a href="/admin/plugins/example#settings" class="text-blue-400 hover:text-blue-300 font-mono">/admin/plugins/example#settings</a></dd>
            </div>
          </dl>
        </div>

        ${user ? `
        <div class="backdrop-blur-md bg-black/20 rounded-xl border border-white/10 p-4 text-sm text-gray-400">
          Logged in as <span class="text-white font-medium">${escapeHtml(user.email)}</span>
          <span class="ml-2 text-xs text-gray-500">(${escapeHtml(user.role)})</span>
        </div>
        ` : ''}

      </div>
    `

    const layoutData: AdminLayoutCatalystData = {
      title: 'Example Plugin',
      pageTitle: 'Example Plugin',
      currentPath: '/admin/example',
      content,
      ...(user ? { user: { name: user.email, email: user.email, role: user.role } } : {}),
      ...(dynamicMenuItems ? { dynamicMenuItems } : {}),
    }

    return c.html(renderAdminLayoutCatalyst(layoutData))
  })

  return router
}
