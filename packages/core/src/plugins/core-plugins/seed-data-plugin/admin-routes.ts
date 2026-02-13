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

function parseNumberOrDefault(value: any, defaultVal: number): number {
  if (value === undefined || value === null || value === '') return defaultVal
  const num = Number(value)
  return isNaN(num) ? defaultVal : num
}

async function loadSettings(db: D1Database): Promise<SeedSettings> {
  try {
    const row = await db
      .prepare('SELECT settings FROM plugins WHERE id = ?')
      .bind('seed-data')
      .first<{ settings: string }>()

    const saved = row?.settings ? JSON.parse(row.settings) : {}
    return {
      userCount: parseNumberOrDefault(saved.userCount, DEFAULTS.userCount),
      contentCount: parseNumberOrDefault(saved.contentCount, DEFAULTS.contentCount),
      formCount: parseNumberOrDefault(saved.formCount, DEFAULTS.formCount),
      submissionsPerForm: parseNumberOrDefault(saved.submissionsPerForm, DEFAULTS.submissionsPerForm),
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
              <input type="number" id="userCount" name="userCount" value="${s.userCount}" min="0" max="100"
                class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500">
              <p class="mt-1 text-xs text-zinc-500">With names, emails, roles (0-100)</p>
            </div>
            <div>
              <label for="contentCount" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Content Items</label>
              <input type="number" id="contentCount" name="contentCount" value="${s.contentCount}" min="0" max="1000"
                class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500">
              <p class="mt-1 text-xs text-zinc-500">Distributed across existing collections (0-1000)</p>
            </div>
            <div>
              <label for="formCount" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Forms to Create</label>
              <input type="number" id="formCount" name="formCount" value="${s.formCount}" min="0" max="20"
                class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500">
              <p class="mt-1 text-xs text-zinc-500">Contact, feedback, registration, etc. (0-20)</p>
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
            <p><strong class="text-zinc-900 dark:text-white">Content:</strong> Distributed across all existing collections — blog posts get multi-paragraph HTML bodies with excerpts and tags, pages get SEO metadata, other collections get contextual data</p>
          </div>
          <div class="space-y-2 text-zinc-600 dark:text-zinc-400">
            <p><strong class="text-zinc-900 dark:text-white">Forms:</strong> Contact, feedback, survey, registration, newsletter, support, job application, product review — with full Form.io schemas</p>
            <p><strong class="text-zinc-900 dark:text-white">Submissions:</strong> Schema-aware field data, IP addresses, user agents, UTM tracking, status workflow</p>
          </div>
        </div>
      </div>

      <!-- Progress Bar (hidden by default) -->
      <div id="progressContainer" class="hidden rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6 mb-6">
        <div class="flex items-center justify-between mb-2">
          <h2 class="text-sm font-semibold text-zinc-950 dark:text-white" id="progressLabel">Generating...</h2>
          <span class="text-sm text-zinc-500 dark:text-zinc-400" id="progressPercent">0%</span>
        </div>
        <div class="w-full bg-zinc-200 dark:bg-zinc-700 rounded-full h-3 overflow-hidden">
          <div id="progressBar" class="bg-indigo-600 h-3 rounded-full transition-all duration-500 ease-out" style="width: 0%"></div>
        </div>
        <p class="mt-2 text-xs text-zinc-500 dark:text-zinc-400" id="progressDetail"></p>
      </div>

      <!-- Generate & Clear Actions -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
          <p class="text-sm text-zinc-500 dark:text-zinc-400 mb-4">Creates users, content, forms, and submissions using the configuration above.</p>
          <button id="generateBtn" onclick="generateSeedData()" class="inline-flex items-center rounded-lg bg-indigo-600 hover:bg-indigo-500 px-4 py-2.5 text-sm font-semibold text-white transition-colors shadow-sm disabled:opacity-50 disabled:cursor-not-allowed">
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"/>
            </svg>
            <span id="generateText">Generate Seed Data</span>
          </button>
        </div>

        <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
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
        var successEl = document.getElementById('successMessage');
        var errorEl = document.getElementById('errorMessage');
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

      function updateProgress(percent, label, detail) {
        var container = document.getElementById('progressContainer');
        var bar = document.getElementById('progressBar');
        var percentEl = document.getElementById('progressPercent');
        var labelEl = document.getElementById('progressLabel');
        var detailEl = document.getElementById('progressDetail');

        container.classList.remove('hidden');
        bar.style.width = percent + '%';
        percentEl.textContent = percent + '%';
        labelEl.textContent = label;
        detailEl.textContent = detail || '';
      }

      function hideProgress() {
        document.getElementById('progressContainer').classList.add('hidden');
      }

      async function saveDefaults() {
        try {
          var res = await fetch('/admin/seed-data/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(getFormValues())
          });
          if (res.ok) {
            var indicator = document.getElementById('savedIndicator');
            indicator.classList.remove('hidden');
            setTimeout(function() { indicator.classList.add('hidden'); }, 2000);
          } else {
            showMessage('error', 'Failed to save defaults');
          }
        } catch (e) {
          showMessage('error', 'Error: ' + e.message);
        }
      }

      async function generateSeedData() {
        var btn = document.getElementById('generateBtn');
        var text = document.getElementById('generateText');
        var clearBtn = document.getElementById('clearBtn');
        btn.disabled = true;
        clearBtn.disabled = true;
        text.textContent = 'Generating...';

        var vals = getFormValues();
        var totals = { users: 0, content: 0, forms: 0, submissions: 0 };
        var steps = [];

        if (vals.userCount > 0) steps.push({ endpoint: 'users', label: 'Creating users...', key: 'users', body: { userCount: vals.userCount } });
        if (vals.contentCount > 0) steps.push({ endpoint: 'content', label: 'Creating content...', key: 'content', body: { contentCount: vals.contentCount, richness: vals.richness } });
        if (vals.formCount > 0) steps.push({ endpoint: 'forms', label: 'Creating forms...', key: 'forms', body: { formCount: vals.formCount } });
        if (vals.formCount > 0 && vals.submissionsPerForm > 0) steps.push({ endpoint: 'submissions', label: 'Creating submissions...', key: 'submissions', body: { submissionsPerForm: vals.submissionsPerForm } });

        if (steps.length === 0) {
          showMessage('error', 'All counts are set to 0. Nothing to generate.');
          btn.disabled = false;
          clearBtn.disabled = false;
          text.textContent = 'Generate Seed Data';
          return;
        }

        try {
          for (var i = 0; i < steps.length; i++) {
            var step = steps[i];
            var pct = Math.round(((i) / steps.length) * 100);
            updateProgress(pct, step.label, 'Step ' + (i + 1) + ' of ' + steps.length);

            var res = await fetch('/admin/seed-data/generate/' + step.endpoint, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(step.body)
            });
            var data = await res.json();
            if (!res.ok || !data.success) {
              throw new Error(data.error || 'Failed at step: ' + step.label);
            }
            totals[step.key] = data.count || 0;
          }

          updateProgress(100, 'Complete!', '');
          setTimeout(hideProgress, 2000);

          var parts = [];
          if (totals.users > 0) parts.push(totals.users + ' users');
          if (totals.content > 0) parts.push(totals.content + ' content items');
          if (totals.forms > 0) parts.push(totals.forms + ' forms');
          if (totals.submissions > 0) parts.push(totals.submissions + ' submissions');
          showMessage('success', 'Created ' + parts.join(', ') + '!');
        } catch (e) {
          hideProgress();
          showMessage('error', 'Error: ' + e.message);
        } finally {
          btn.disabled = false;
          clearBtn.disabled = false;
          text.textContent = 'Generate Seed Data';
        }
      }

      async function clearSeedData() {
        if (!confirm('Are you sure you want to clear ALL data? This removes all content, forms, submissions, and non-admin users. This cannot be undone!')) return;

        var btn = document.getElementById('clearBtn');
        var text = document.getElementById('clearText');
        btn.disabled = true;
        text.textContent = 'Clearing...';

        try {
          var res = await fetch('/admin/seed-data/clear', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          var data = await res.json();
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
        userCount: Math.min(Math.max(parseNumberOrDefault(body.userCount, DEFAULTS.userCount), 0), 100),
        contentCount: Math.min(Math.max(parseNumberOrDefault(body.contentCount, DEFAULTS.contentCount), 0), 1000),
        formCount: Math.min(Math.max(parseNumberOrDefault(body.formCount, DEFAULTS.formCount), 0), 20),
        submissionsPerForm: Math.min(Math.max(parseNumberOrDefault(body.submissionsPerForm, DEFAULTS.submissionsPerForm), 0), 100),
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

  // Step-based generation endpoints
  routes.post('/generate/users', async (c) => {
    try {
      const db = c.env.DB
      const body = await c.req.json()
      const userCount = Math.min(Math.max(parseNumberOrDefault(body.userCount, 0), 0), 100)
      if (userCount === 0) return c.json({ success: true, count: 0 })

      const seedService = new SeedDataService(db)
      const count = await seedService.createUsers(userCount)
      return c.json({ success: true, count })
    } catch (error: any) {
      console.error('[Seed Data] Users error:', error)
      return c.json({ success: false, error: error.message }, 500)
    }
  })

  routes.post('/generate/content', async (c) => {
    try {
      const db = c.env.DB
      const body = await c.req.json()
      const contentCount = Math.min(Math.max(parseNumberOrDefault(body.contentCount, 0), 0), 1000)
      const richness = body.richness === 'minimal' ? 'minimal' as const : 'full' as const
      if (contentCount === 0) return c.json({ success: true, count: 0 })

      const seedService = new SeedDataService(db)
      const count = await seedService.createContent(contentCount, richness)
      return c.json({ success: true, count })
    } catch (error: any) {
      console.error('[Seed Data] Content error:', error)
      return c.json({ success: false, error: error.message }, 500)
    }
  })

  routes.post('/generate/forms', async (c) => {
    try {
      const db = c.env.DB
      const body = await c.req.json()
      const formCount = Math.min(Math.max(parseNumberOrDefault(body.formCount, 0), 0), 20)
      if (formCount === 0) return c.json({ success: true, count: 0 })

      const { results: admins } = await db.prepare("SELECT id FROM users WHERE role = 'admin' LIMIT 1").all()
      const creatorId = (admins?.[0] as any)?.id || 'system'

      const seedService = new SeedDataService(db)
      const { forms } = await seedService.createForms(formCount, creatorId)
      return c.json({ success: true, count: forms })
    } catch (error: any) {
      console.error('[Seed Data] Forms error:', error)
      return c.json({ success: false, error: error.message }, 500)
    }
  })

  routes.post('/generate/submissions', async (c) => {
    try {
      const db = c.env.DB
      const body = await c.req.json()
      const submissionsPerForm = Math.min(Math.max(parseNumberOrDefault(body.submissionsPerForm, 0), 0), 100)
      if (submissionsPerForm === 0) return c.json({ success: true, count: 0 })

      // Get all forms
      const { results: forms } = await db.prepare('SELECT id, formio_schema FROM forms').all<{ id: string; formio_schema: string }>()
      if (!forms || forms.length === 0) return c.json({ success: true, count: 0 })

      // Get all users for submission assignment
      const { results: allUsers } = await db.prepare('SELECT id, email FROM users').all()

      const seedService = new SeedDataService(db)
      let totalSubmissions = 0
      for (const form of forms) {
        const schema = JSON.parse(form.formio_schema)
        const created = await seedService.createSubmissions(form.id, schema, submissionsPerForm, allUsers || [])
        totalSubmissions += created
      }
      return c.json({ success: true, count: totalSubmissions })
    } catch (error: any) {
      console.error('[Seed Data] Submissions error:', error)
      return c.json({ success: false, error: error.message }, 500)
    }
  })

  // Legacy single-call generate (kept for backward compatibility)
  routes.post('/generate', async (c) => {
    try {
      const db = c.env.DB
      const body = await c.req.json()

      const options: SeedOptions = {
        userCount: Math.min(Math.max(parseNumberOrDefault(body.userCount, DEFAULTS.userCount), 0), 100),
        contentCount: Math.min(Math.max(parseNumberOrDefault(body.contentCount, DEFAULTS.contentCount), 0), 1000),
        formCount: Math.min(Math.max(parseNumberOrDefault(body.formCount, DEFAULTS.formCount), 0), 20),
        submissionsPerForm: Math.min(Math.max(parseNumberOrDefault(body.submissionsPerForm, DEFAULTS.submissionsPerForm), 0), 100),
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
