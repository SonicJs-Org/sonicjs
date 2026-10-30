/**
 * Hello World Plugin — Payload-shaped pilot port.
 *
 * Demonstrates the v4 plugin shape: definePlugin(...) with declarative menu
 * + configSchema + sync register. Replaces the legacy PluginBuilder fluent
 * API. Keeps the same id/version/routes so existing tests and the manifest
 * registry continue to resolve it.
 */

import { Hono } from 'hono'
import { html } from 'hono/html'
import { definePlugin } from '../../sdk/define-plugin'

const helloWorldRoutes = new Hono()

helloWorldRoutes.get('/', async (c: any) => {
  const user = c.get('user') as { email?: string; role?: string } | undefined
  const settings = (c.get('_helloWorldSettings') ?? { greeting: 'Hello World!' }) as { greeting: string }

  return c.html(html`
    <!DOCTYPE html>
    <html lang="en" class="dark">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, 1.0">
        <title>Hello World - SonicJS</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script>tailwind.config = { darkMode: 'class' }</script>
      </head>
      <body class="bg-white dark:bg-zinc-950 text-zinc-950 dark:text-white min-h-screen">
        <main class="p-8 max-w-2xl mx-auto">
          <h1 class="text-3xl font-bold mb-2">Hello World</h1>
          <p class="text-zinc-600 dark:text-zinc-400 mb-6">Welcome to the Hello World plugin!</p>
          <div class="bg-white dark:bg-zinc-900 rounded-lg border border-zinc-200 dark:border-zinc-800 shadow-sm p-8 text-center">
            <span class="text-6xl">👋</span>
            <h2 class="text-4xl font-bold my-4 bg-gradient-to-r from-blue-500 to-purple-600 bg-clip-text text-transparent">
              ${settings.greeting}
            </h2>
            <div class="bg-zinc-50 dark:bg-zinc-800 rounded-lg p-4 text-left mt-6">
              <h3 class="font-semibold mb-2">Plugin Information:</h3>
              <ul class="text-sm text-zinc-600 dark:text-zinc-400 space-y-1">
                <li><strong>Plugin ID:</strong> hello-world</li>
                <li><strong>Version:</strong> 1.0.0</li>
                <li><strong>User:</strong> ${user?.email || 'Not logged in'}</li>
                <li><strong>Role:</strong> ${user?.role || 'N/A'}</li>
              </ul>
            </div>
          </div>
        </main>
      </body>
    </html>
  `)
})

export const helloWorldPlugin = definePlugin({
  id: 'hello-world',
  version: '1.0.0',
  name: 'Hello World',
  description: 'A simple demonstration plugin.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS Team', email: 'team@sonicjs.com' },

  register(app) {
    app.route('/admin/hello-world', helloWorldRoutes)
  },

  menu: [
    {
      label: 'Hello World',
      path: '/admin/hello-world',
      icon: 'sparkles',
      order: 90,
      permissions: ['hello-world:view'],
    },
  ],

  configSchema: {
    greeting: {
      type: 'string',
      label: 'Greeting',
      description: 'Text displayed on the Hello World page.',
      default: 'Hello World!',
      placeholder: 'Hello World!',
    },
  },

  activate: async () => {
    console.info('✅ Hello World plugin activated')
  },
  deactivate: async () => {
    console.info('❌ Hello World plugin deactivated')
  },
})

// Backwards-compatible factory export — kept so callers that import the
// factory keep compiling without a touch. Returns the same singleton.
export function createHelloWorldPlugin() {
  return helloWorldPlugin
}
