# Build a Hello World Plugin from Scratch

This tutorial walks you through building a SonicJS plugin from zero. By the end you will have a working admin page that greets a configurable name — "Hello, Joe!" — with the name editable from the plugin settings UI.

---

## What you will build

- A plugin at `my-sonicjs-app/src/plugins/hello-world/index.ts`
- An admin page at `/admin/hello-world` that reads a `recipientName` setting and displays "Hello, {name}!"
- A settings form auto-generated at `/admin/plugins/hello-world/configure`
- A sidebar link in the admin panel

---

## 1. Create the plugin file

```ts
// my-sonicjs-app/src/plugins/hello-world/index.ts

import { Hono } from 'hono'
import { html } from 'hono/html'
import { definePlugin } from '@sonicjs-cms/core'

const routes = new Hono()

routes.get('/', async (c) => {
  // Read settings saved by the admin settings form
  const row = await c.env.DB
    .prepare(`SELECT settings FROM plugins WHERE id = 'hello-world'`)
    .first<{ settings: string | null }>()

  const settings: { recipientName?: string } =
    row?.settings ? JSON.parse(row.settings) : {}

  const name = settings.recipientName ?? 'World'

  return c.html(html`
    <!DOCTYPE html>
    <html lang="en" class="dark">
      <head>
        <meta charset="UTF-8" />
        <title>Hello World — SonicJS</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script>tailwind.config = { darkMode: 'class' }</script>
      </head>
      <body class="bg-white dark:bg-zinc-950 text-zinc-950 dark:text-white min-h-screen flex items-center justify-center">
        <div class="text-center">
          <p class="text-6xl mb-6">👋</p>
          <h1 class="text-5xl font-bold bg-gradient-to-r from-blue-500 to-purple-600 bg-clip-text text-transparent">
            Hello, ${name}!
          </h1>
          <p class="mt-4 text-zinc-500 dark:text-zinc-400 text-sm">
            Change the name at
            <a href="/admin/plugins/hello-world/configure" class="underline">Plugin Settings</a>
          </p>
        </div>
      </body>
    </html>
  `)
})

export const helloWorldPlugin = definePlugin({
  id: 'hello-world',
  version: '1.0.0',
  name: 'Hello World',
  description: 'Greets a configurable name. Great starting point for custom plugins.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'Your Name', email: 'you@example.com' },

  // Mount routes synchronously — must NOT be async
  register(app) {
    app.route('/admin/hello-world', routes)
  },

  // Settings form — auto-generated at /admin/plugins/hello-world/configure
  configSchema: {
    recipientName: {
      type: 'string',
      label: 'Name to greet',
      description: 'The name shown on the Hello World page.',
      default: 'World',
      placeholder: 'e.g. Joe',
    },
  },

  // Sidebar link
  menu: [
    {
      label: 'Hello World',
      path: '/admin/hello-world',
      icon: 'sparkles',
      order: 90,
      permissions: ['hello-world:view'],
    },
  ],

  activate:   async () => console.info('Hello World plugin activated'),
  deactivate: async () => console.info('Hello World plugin deactivated'),
})
```

---

## 2. Register the plugin

Open `my-sonicjs-app/src/index.ts` and add the import + register entry:

```ts
import { createSonicJSApp, registerCollections } from '@sonicjs-cms/core'
import type { SonicJSConfig } from '@sonicjs-cms/core'
import { helloWorldPlugin } from './plugins/hello-world'

// ... your collection registrations ...

const config: SonicJSConfig = {
  plugins: {
    register: [helloWorldPlugin],
  },
}

const app = createSonicJSApp(config)
export default { fetch: app.fetch }
```

> **Note:** if you are registering multiple plugins, add them all to the `register` array:
> ```ts
> register: [helloWorldPlugin, myOtherPlugin],
> ```

---

## 3. Start the dev server

```bash
cd my-sonicjs-app && npm run dev
```

Navigate to `http://localhost:8787/admin/hello-world`. You should see:

> **Hello, World!**

---

## 4. Personalise the greeting

1. Go to `http://localhost:8787/admin/plugins/hello-world/configure`
2. Enter a name in the **Name to greet** field — e.g. `Joe`
3. Click **Save**
4. Go back to `http://localhost:8787/admin/hello-world`

You should now see:

> **Hello, Joe!**

---

## 5. How it works

| Piece | What it does |
|---|---|
| `definePlugin({ id, ... })` | Registers the plugin with the core runtime |
| `register(app) { app.route(...) }` | Mounts Hono routes **synchronously** at app startup |
| `configSchema` | Declares typed fields — SonicJS auto-generates the settings form |
| `menu: [...]` | Adds a sidebar entry in the admin panel |
| `c.env.DB.prepare(...)` | Reads the saved settings at request time |

### Why read settings in the route handler?

Plugin settings are stored in the `plugins` table and can be changed at any time by an admin. Reading them per-request (rather than caching at boot) means updates take effect immediately without a restart.

### Why `register` must be sync

Hono locks its router after the first request. Any `async` inside `register` would race with incoming traffic. Keep `register` synchronous and put DB/KV work inside `onBoot` or request handlers.

---

## 6. Next steps

- Add more settings fields (see the `configSchema` field type table in `docs/plugins/v4-author-guide.md` §5)
- Add API routes under `/api/hello-world/` alongside the admin routes
- Subscribe to hooks in `onBoot` (see §4 of the author guide)
- Add a cron job with `crons: [...]` + `onCronTick` (see §7 of the author guide)
- Write an integration test in `__tests__/*.integration.test.ts` and an E2E spec in `tests/e2e/`
