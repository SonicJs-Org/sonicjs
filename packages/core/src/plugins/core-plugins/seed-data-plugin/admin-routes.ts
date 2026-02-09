import { Hono } from 'hono'
import type { D1Database } from '@cloudflare/workers-types'
import { SeedDataService } from './services/seed-data-service'
import type { SeedOptions } from './services/seed-data-service'
import { renderAdminLayout } from '../../../templates/layouts/admin-layout-v2.template'

type Bindings = {
  DB: D1Database
}

interface SeedSettings {
  userCount: number
  contentCount: number
  formCount: number
  submissionsPerForm: number
  richness: 'minimal' | 'full'
}

const DEFAULTS: SeedSettings = {
  userCount: 20,
  contentCount: 200,
  formCount: 5,
  submissionsPerForm: 15,
  richness: 'full'
}

async function loadSettings(db: D1Database): Promise<SeedSettings> {
  try {
    const row = await db
      .prepare('SELECT settings FROM plugins WHERE id = ?')
      .bind('seed-data')
      .first<{ settings: string }>()

    const saved = row?.settings ? JSON.parse(row.settings) : {}
    return {
      userCount: saved.userCount || DEFAULTS.userCount,
      contentCount: saved.contentCount || DEFAULTS.contentCount,
      formCount: saved.formCount || DEFAULTS.formCount,
      submissionsPerForm: saved.submissionsPerForm || DEFAULTS.submissionsPerForm,
      richness: saved.richness || DEFAULTS.richness
    }
  } catch {
    return { ...DEFAULTS }
  }
}

export function createSeedDataAdminRoutes() {
  const routes = new Hono<{ Bindings: Bindings }>()

  // Settings page
  routes.get('/', async (c) => {
    const db = c.env.DB
    const s = await loadSettings(db)

    const content = `
    <div class="w-full px-4 sm:px-6 lg:px-8 py-6">
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6">
        <div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">Seed Data Generator</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">
            Generate realistic users, content, forms, and submissions for testing and development.
          </p>
        </div>
        <div class="mt-4 sm:mt-0">
          <a href="/admin/plugins" class="inline-flex items-center justify-center rounded-lg bg-white dark:bg-zinc-800 px-3.5 py-2.5 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors shadow-sm">
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/>
            </svg>
            Back to Plugins
          </a>
        </div>
      </div>

      <!-- Warning Banner -->
      <div class="rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 p-4 mb-6">
        <div class="flex items-center gap-2">
          <span class="text-amber-600 dark:text-amber-400 font-semibold">Warning:</span>
          <span class="text-sm text-amber-700 dark:text-amber-300">This tool creates test data in your database. Do not use in production!</span>
        </div>
      </div>

      <!-- Status Messages -->
      <div id="successMessage" class="hidden rounded-lg bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 p-4 mb-6">
        <span class="text-sm font-medium text-green-800 dark:text-green-200" id="successText"></span>
      </div>
      <div id="errorMessage" class="hidden rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-4 mb-6">
        <span class="text-sm font-medium text-red-800 dark:text-red-200" id="errorText"></span>
      </div>

      <!-- Configuration Card -->
      <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6 mb-6">
        <h2 class="text-lg font-semibold text-zinc-950 dark:text-white mb-4">Configuration</h2>
        <form id="seedForm" class="space-y-6">
          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div>
              <label for="userCount" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Users to Create</label>
              <input type="number" id="userCount" name="userCount" value="${s.userCount}" min="1" max="100"
                class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500">
              <p class="mt-1 text-xs text-zinc-500">With names, emails, roles (1-100)</p>
            </div>
            <div>
              <label for="contentCount" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Content Items</label>
              <input type="number" id="contentCount" name="contentCount" value="${s.contentCount}" min="10" max="1000"
                class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500">
              <p class="mt-1 text-xs text-zinc-500">Blog posts, pages, products (10-1000)</p>
            </div>
            <div>
              <label for="formCount" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Forms to Create</label>
              <input type="number" id="formCount" name="formCount" value="${s.formCount}" min="1" max="20"
                class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500">
              <p class="mt-1 text-xs text-zinc-500">Contact, feedback, registration, etc. (1-20)</p>
            </div>
            <div>
              <label for="submissionsPerForm" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Submissions per Form</label>
              <input type="number" id="submissionsPerForm" name="submissionsPerForm" value="${s.submissionsPerForm}" min="0" max="100"
                class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500">
              <p class="mt-1 text-xs text-zinc-500">Realistic submissions per form (0-100)</p>
            </div>
            <div>
              <label for="richness" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Content Richness</label>
              <select id="richness" name="richness"
                class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500">
                <option value="full" ${s.richness === 'full' ? 'selected' : ''}>Full — Multi-paragraph content, SEO metadata, specs</option>
                <option value="minimal" ${s.richness === 'minimal' ? 'selected' : ''}>Minimal — Single-sentence bodies, basic fields</option>
              </select>
              <p class="mt-1 text-xs text-zinc-500">Depth of generated content</p>
            </div>
          </div>

          <div class="flex items-center gap-3 pt-2">
            <button type="button" onclick="saveDefaults()" class="inline-flex items-center rounded-lg bg-white dark:bg-zinc-800 px-4 py-2 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors">
              Save as Defaults
            </button>
            <span id="savedIndicator" class="hidden text-sm text-green-600 dark:text-green-400">Saved!</span>
          </div>
        </form>
      </div>

      <!-- What Gets Created -->
      <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6 mb-6">
        <h2 class="text-lg font-semibold text-zinc-950 dark:text-white mb-3">What Gets Created</h2>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div class="space-y-2 text-zinc-600 dark:text-zinc-400">
            <p><strong class="text-zinc-900 dark:text-white">Users:</strong> Realistic names, emails, roles (admin/editor/author/viewer), activity dates</p>
            <p><strong class="text-zinc-900 dark:text-white">Blog Posts:</strong> Multi-paragraph HTML bodies, excerpts, tags, difficulty levels, reading time</p>
            <p><strong class="text-zinc-900 dark:text-white">Pages:</strong> About, FAQ, Privacy Policy, etc. with SEO metadata</p>
          </div>
          <div class="space-y-2 text-zinc-600 dark:text-zinc-400">
            <p><strong class="text-zinc-900 dark:text-white">Products:</strong> Detailed descriptions, specs, ratings, reviews, pricing, SKUs</p>
            <p><strong class="text-zinc-900 dark:text-white">Forms:</strong> Contact, feedback, survey, registration, newsletter, support, job application, product review — with full Form.io schemas</p>
            <p><strong class="text-zinc-900 dark:text-white">Submissions:</strong> Schema-aware field data, IP addresses, user agents, UTM tracking, status workflow</p>
          </div>
        </div>
      </div>

      <!-- Generate & Clear Actions -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
          <h2 class="text-lg font-semibold text-zinc-950 dark:text-white mb-2">Generate Seed Data</h2>
          <p class="text-sm text-zinc-500 dark:text-zinc-400 mb-4">Creates users, content, forms, and submissions using the configuration above.</p>
          <button id="generateBtn" onclick="generateSeedData()" class="inline-flex items-center rounded-lg bg-indigo-600 hover:bg-indigo-500 px-4 py-2.5 text-sm font-semibold text-white transition-colors shadow-sm disabled:opacity-50 disabled:cursor-not-allowed">
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"/>
            </svg>
            <span id="generateText">Generate Data</span>
          </button>
        </div>

        <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
          <h2 class="text-lg font-semibold text-red-600 dark:text-red-400 mb-2">Clear All Data</h2>
          <p class="text-sm text-zinc-500 dark:text-zinc-400 mb-4">Removes all content, forms, submissions, and non-admin users. Cannot be undone.</p>
          <button id="clearBtn" onclick="clearSeedData()" class="inline-flex items-center rounded-lg bg-red-600 hover:bg-red-500 px-4 py-2.5 text-sm font-semibold text-white transition-colors shadow-sm disabled:opacity-50 disabled:cursor-not-allowed">
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
            </svg>
            <span id="clearText">Clear All Data</span>
          </button>
        </div>
      </div>
    </div>

    <script>
      function getFormValues() {
        return {
          userCount: Number(document.getElementById('userCount').value),
          contentCount: Number(document.getElementById('contentCount').value),
          formCount: Number(document.getElementById('formCount').value),
          submissionsPerForm: Number(document.getElementById('submissionsPerForm').value),
          richness: document.getElementById('richness').value
        };
      }

      function showMessage(type, text) {
        const successEl = document.getElementById('successMessage');
        const errorEl = document.getElementById('errorMessage');
        successEl.classList.add('hidden');
        errorEl.classList.add('hidden');

        if (type === 'success') {
          document.getElementById('successText').textContent = text;
          successEl.classList.remove('hidden');
        } else {
          document.getElementById('errorText').textContent = text;
          errorEl.classList.remove('hidden');
        }
      }

      async function saveDefaults() {
        try {
          const res = await fetch('/admin/seed-data/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(getFormValues())
          });
          if (res.ok) {
            const indicator = document.getElementById('savedIndicator');
            indicator.classList.remove('hidden');
            setTimeout(() => indicator.classList.add('hidden'), 2000);
          } else {
            showMessage('error', 'Failed to save defaults');
          }
        } catch (e) {
          showMessage('error', 'Error: ' + e.message);
        }
      }

      async function generateSeedData() {
        const btn = document.getElementById('generateBtn');
        const text = document.getElementById('generateText');
        btn.disabled = true;
        text.textContent = 'Generating...';

        try {
          const res = await fetch('/admin/seed-data/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(getFormValues())
          });
          const data = await res.json();
          if (res.ok && data.success) {
            showMessage('success',
              'Created ' + data.users + ' users, ' + data.content + ' content items, ' +
              data.forms + ' forms, and ' + data.submissions + ' submissions!'
            );
          } else {
            throw new Error(data.error || 'Generation failed');
          }
        } catch (e) {
          showMessage('error', 'Error: ' + e.message);
        } finally {
          btn.disabled = false;
          text.textContent = 'Generate Data';
        }
      }

      async function clearSeedData() {
        if (!confirm('Are you sure you want to clear ALL data? This removes all content, forms, submissions, and non-admin users. This cannot be undone!')) return;

        const btn = document.getElementById('clearBtn');
        const text = document.getElementById('clearText');
        btn.disabled = true;
        text.textContent = 'Clearing...';

        try {
          const res = await fetch('/admin/seed-data/clear', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          const data = await res.json();
          if (res.ok && data.success) {
            showMessage('success', 'All seed data cleared successfully!');
          } else {
            throw new Error(data.error || 'Clear failed');
          }
        } catch (e) {
          showMessage('error', 'Error: ' + e.message);
        } finally {
          btn.disabled = false;
          text.textContent = 'Clear All Data';
        }
      }
    </script>
    `

    return c.html(renderAdminLayout({
      title: 'Seed Data Generator',
      pageTitle: 'Seed Data Generator',
      currentPath: '/admin/seed-data',
      content
    }))
  })

  // Save default settings
  routes.post('/settings', async (c) => {
    try {
      const db = c.env.DB
      const body = await c.req.json()

      const settings: SeedSettings = {
        userCount: Math.min(Math.max(Number(body.userCount) || DEFAULTS.userCount, 1), 100),
        contentCount: Math.min(Math.max(Number(body.contentCount) || DEFAULTS.contentCount, 10), 1000),
        formCount: Math.min(Math.max(Number(body.formCount) || DEFAULTS.formCount, 1), 20),
        submissionsPerForm: Math.min(Math.max(Number(body.submissionsPerForm) || 0, 0), 100),
        richness: body.richness === 'minimal' ? 'minimal' : 'full'
      }

      await db.prepare(
        'UPDATE plugins SET settings = ? WHERE id = ?'
      ).bind(JSON.stringify(settings), 'seed-data').run()

      return c.json({ success: true, settings })
    } catch (error: any) {
      return c.json({ success: false, error: error.message }, 500)
    }
  })

  // Generate seed data
  routes.post('/generate', async (c) => {
    try {
      const db = c.env.DB
      const body = await c.req.json()

      const options: SeedOptions = {
        userCount: Math.min(Math.max(Number(body.userCount) || DEFAULTS.userCount, 1), 100),
        contentCount: Math.min(Math.max(Number(body.contentCount) || DEFAULTS.contentCount, 10), 1000),
        formCount: Math.min(Math.max(Number(body.formCount) || DEFAULTS.formCount, 1), 20),
        submissionsPerForm: Math.min(Math.max(Number(body.submissionsPerForm) || 0, 0), 100),
        richness: body.richness === 'minimal' ? 'minimal' : 'full'
      }

      const seedService = new SeedDataService(db)
      const result = await seedService.seedAll(options)

      return c.json({ success: true, ...result })
    } catch (error: any) {
      console.error('[Seed Data] Generation error:', error)
      return c.json({ success: false, error: error.message }, 500)
    }
  })

  // Clear all seed data
  routes.post('/clear', async (c) => {
    try {
      const db = c.env.DB
      const seedService = new SeedDataService(db)
      await seedService.clearSeedData()
      return c.json({ success: true })
    } catch (error: any) {
      console.error('[Seed Data] Clear error:', error)
      return c.json({ success: false, error: error.message }, 500)
    }
  })

  return routes
}
