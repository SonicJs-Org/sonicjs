import { APIRequestContext, BrowserContext, Page, expect, test } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Better Auth enforces CSRF by rejecting a missing/null/untrusted Origin (MISSING_OR_NULL_ORIGIN).
// Playwright's page.request from about:blank sends a null Origin, so every auth API call below must
// send the server origin explicitly. Matches the baseURL resolution in tests/playwright.config.ts.
export const TEST_ORIGIN = process.env.BASE_URL || 'http://localhost:8787';

// True when running against a non-localhost deployment (e.g. CI preview).
// Tenant tests use `wrangler d1 execute --local` which only affects local SQLite,
// not the remote worker's D1 — skip those tests in remote deployments.
export const IS_REMOTE_DEPLOYMENT = !TEST_ORIGIN.includes('localhost') && !TEST_ORIGIN.includes('127.0.0.1');

const APP_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '../../../my-sonicjs-app');

/**
 * Run one SQL statement against the dev server's *local* D1 (the same .wrangler state the
 * running worker uses). Used by the tenant specs to seed and clean rows the admin UI has no
 * route for.
 *
 * Retries on SQLITE_BUSY: this opens the very SQLite file `wrangler dev` holds open, so a write
 * that lands while the worker is mid-transaction is refused outright rather than queued. It
 * surfaced as `Command failed: npx wrangler d1 execute … NOSENTRY database is locked:
 * SQLITE_BUSY` in whichever tenant test happened to be unlucky, naming nothing about tenancy.
 *
 * Shared rather than copy-pasted: six specs had their own one-line version of this, so the
 * retry had to be added six times or it protected only the file it was written in.
 */
export function d1Exec(sql: string) {
  const ATTEMPTS = 5;
  for (let attempt = 1; ; attempt++) {
    try {
      execFileSync('npx', ['wrangler', 'd1', 'execute', 'DB', '--local', '--command', sql], {
        cwd: APP_DIR,
        stdio: 'pipe',
      });
      return;
    } catch (error) {
      const output = `${(error as { stderr?: Buffer }).stderr ?? ''}${(error as Error).message ?? ''}`;
      if (attempt === ATTEMPTS || !/SQLITE_BUSY|database is locked/i.test(output)) throw error;
      // Synchronous on purpose: the callers are sync beforeAll/afterAll hooks.
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 400 * attempt);
    }
  }
}

/**
 * Predicate for `page.waitForURL` after a form POST that redirects back with a `?message=`
 * flash.
 *
 * Matching on the message, not just the path, is the whole point: several of these handlers
 * redirect to the very URL the form was submitted from (`/admin/tenants/new` -> `/admin/tenants`
 * matches `/\/admin\/tenants/` before the click even dispatches), so a path-only pattern is
 * already true and `waitForURL` resolves instantly, leaving the assertions below to run against
 * the pre-submit page. A predicate rather than a regex over the href because the handlers are
 * inconsistent about percent-encoding the message, and `searchParams` decodes either form.
 */
export const flashedTo =
  (pathname: string | RegExp, expected: string | RegExp) =>
  (url: URL): boolean => {
    const pathOk =
      typeof pathname === 'string' ? url.pathname === pathname : pathname.test(url.pathname)
    if (!pathOk) return false
    const message = url.searchParams.get('message') ?? ''
    return typeof expected === 'string' ? message.includes(expected) : expected.test(message)
  }

/**
 * Click something that submits a native form, and wait for the document the server redirects to.
 *
 * `page.waitForLoadState('networkidle')` straight after the click is not that wait: it reports
 * on the page you are still on, so it can resolve before the navigation has even committed and
 * leave the assertions below reading the pre-submit DOM. For a "did this persist?" test that DOM
 * still holds the value the test itself typed, so it passes whether or not anything was written.
 */
export async function submitAndWaitForDocument(
  page: Page,
  pathname: string | RegExp,
  click: () => Promise<void>
): Promise<void> {
  const matches = (p: string) => (typeof pathname === 'string' ? p === pathname : pathname.test(p))
  await Promise.all([
    page.waitForResponse(
      (r) =>
        r.request().resourceType() === 'document' &&
        r.request().method() === 'GET' &&
        matches(new URL(r.url()).pathname)
    ),
    click(),
  ])
  await page.waitForLoadState('domcontentloaded')
}

/**
 * Save a form htmx submits with a verb an HTML form cannot send (PUT/DELETE), and wait for the
 * response instead of for `networkidle`.
 *
 * `waitForLoadState('networkidle')` can resolve before htmx has even issued the XHR — the page
 * is quiet at that instant precisely because the request has not started. The next `page.goto`
 * then cancels the in-flight save, the write silently never lands, and the failure surfaces
 * several steps later as an unrelated-looking assertion.
 */
export async function submitAndWaitForXhr(
  page: Page,
  method: string,
  urlPart: string,
  click: () => Promise<void>
): Promise<void> {
  const [res] = await Promise.all([
    page.waitForResponse((r) => r.request().method() === method && r.url().includes(urlPart)),
    click(),
  ])
  expect(res.ok(), `${method} ${urlPart} failed: ${res.status()}`).toBeTruthy()
}

/**
 * Save the open `/admin/content/new` form and return the created record's edit path.
 *
 * The create answers the htmx POST with `HX-Redirect: /admin/content/<rootId>/edit`, and that
 * header is its only success signal: both failure paths in the handler answer the same POST with
 * HTML — the error banner at 200 and "Collection is not document-backed" at 400 — so neither
 * `res.ok()` nor the eventual URL distinguishes a failed create from a slow one.
 *
 * `page.waitForURL(/\/edit/)` on its own spends the whole budget blind. It cannot tell "the save
 * is still in flight" from "the save came back with a validation error and htmx is never going to
 * navigate", and it reports both as a navigation timeout pointing at fixtures.ts. Three specs
 * flaked or failed that way in CI run 39582792718. Read the header first, then wait for the
 * navigation htmx is about to make.
 */
export async function saveNewContent(page: Page, click: () => Promise<void>): Promise<string> {
  const [res] = await Promise.all([
    page.waitForResponse(
      (r) => r.request().method() === 'POST' && new URL(r.url()).pathname === '/admin/content'
    ),
    click(),
  ])

  const redirect = res.headers()['hx-redirect']
  const editPath = redirect ? new URL(redirect, page.url()).pathname : ''
  if (!/^\/admin\/content\/[^/]+\/edit$/.test(editPath)) {
    throw new Error(
      `Content create did not redirect to an edit form (HTTP ${res.status()}, HX-Redirect ` +
        `${redirect || 'absent'}): ${(await res.text()).slice(0, 300)}`
    )
  }

  // htmx sets location *after* the response, so the URL is still /admin/content/new at this point.
  await page.waitForURL((url) => url.pathname === editPath, { timeout: 15000 })
  return editPath
}

// Default admin credentials for testing
export const ADMIN_CREDENTIALS = {
  email: 'admin@sonicjs.com',
  password: 'sonicjs!'
};

// Test data
export const TEST_DATA = {
  collection: {
    name: 'test_collection',
    displayName: 'Test Collection',
    description: 'Test collection for E2E testing'
  },
  content: {
    title: 'Test Blog Post',
    content: '<h1>Test Content</h1><p>This is test content for E2E testing.</p>',
    excerpt: 'Test excerpt for blog post',
    tags: ['test', 'e2e', 'playwright']
  },
  user: {
    email: 'testuser@example.com',
    username: 'testuser',
    firstName: 'Test',
    lastName: 'User',
    password: 'testpass123'
  }
};

/**
 * Extract CSRF token value from Set-Cookie response header.
 * Works with Playwright's newline-joined Set-Cookie format.
 */
export function extractCsrfToken(setCookieHeader: string | undefined): string {
  if (!setCookieHeader) return '';
  const match = setCookieHeader.match(/csrf_token=([^;\s]+)/);
  return match ? match[1] : '';
}

/**
 * Get CSRF token from page context cookies.
 * Use with page.request.post() calls that need CSRF headers.
 */
export async function getCsrfTokenFromPage(page: Page): Promise<string> {
  const cookies = await page.context().cookies();
  const csrfCookie = cookies.find(c => c.name === 'csrf_token');
  return csrfCookie?.value || '';
}

/**
 * Ensure admin user exists (for testing)
 *
 * `/auth/seed-admin` is rate limited to 10 requests per minute and this runs from the beforeEach
 * of ~36 specs, so seeding on every test spent the window and the endpoint answered 429 to
 * whoever asked next — including `114-seed-admin-env-gate`, which asserts on the seeder's own
 * response. That was first fixed with a 30s TTL, which is still ~40 windows per worker over an
 * E2E phase: ~160 requests across four workers.
 *
 * None of them do anything. The seed is idempotent, the preview D1 is created fresh for the run,
 * and nothing in the suite mutates `admin@sonicjs.com` — `115-admin-set-password` creates its own
 * user, and the 2FA specs leave state the seeder does not touch either (hence the explicit
 * two-factor error in `signInAsAdmin`). So a re-seed restores nothing that was lost.
 *
 * It is not free, either. `upsertSeedUser` calls `AuthManager.hashPassword` *before* it checks
 * whether the user exists, and runs twice per request (admin + editor), so every one of those
 * requests is two scrypt hashes plus `bootstrapDocumentTypes` and `ensureSystemRbacSeed`. Hashing
 * serializes in the isolate — the same cost that put 120s hangs in `loginAsAdmin`'s beforeEach
 * and is why sign-in is now cached per worker.
 *
 * So: latch on success, once per worker.
 *
 * On *success* specifically — `request.post()` resolves for a 429 and a 500 just as it does for a
 * 200, because Playwright only rejects on a transport error. Latching in `.then()` therefore
 * latched failures too: the first worker to be told "rate limited, another worker is seeding" or
 * to hit a cold-isolate 500 would mark itself seeded and never ask again, and if every worker's
 * first attempt landed that way nobody would seed at all while all four believed somebody had.
 * `res.ok()` is the only thing that means the handler ran.
 *
 * Retries are capped rather than unbounded: if the endpoint is refusing for a reason waiting will
 * not fix — `ENABLE_SEED_ADMIN` unset, a production `ENVIRONMENT` — then every test's beforeEach
 * would otherwise POST again, spending the 10/min window on requests that cannot succeed. Three
 * attempts is enough to ride out a cold start or one worker's 429 without becoming a storm.
 */
const MAX_SEED_ATTEMPTS = 3;
let seeded = false;
let seedAttempts = 0;
let seedInFlight: Promise<void> | null = null;

type SeedClient = {
  post: (url: string, options?: any) => Promise<{ ok: () => boolean; status: () => number }>;
};

async function seedAdminOnce(client: SeedClient) {
  if (seeded || seedAttempts >= MAX_SEED_ATTEMPTS) return;
  if (!seedInFlight) {
    seedAttempts += 1;
    seedInFlight = client
      .post('/auth/seed-admin')
      .then((res) => { seeded = res.ok(); })
      .catch(() => { /* transport error — not latched, so the next caller retries */ })
      .finally(() => { seedInFlight = null; });
  }
  await seedInFlight;
}

export async function ensureAdminUserExists(page: Page) {
  await seedAdminOnce(page.request);
}

/**
 * POST /auth/seed-admin until a request actually reaches the handler.
 *
 * The route is rate-limited to 10 requests per minute per IP
 * (`rateLimit({ max: 10, windowMs: 60_000, keyPrefix: 'seed-admin' })` in routes/auth.ts), so in
 * a full-suite run the window can already be spent by the time a test that asserts on the
 * seeder's own response gets a turn. A 429 is the limiter answering, not the seeder, and
 * asserting on whichever request happened to land first tests the wrong thing.
 *
 * Polled rather than slept out via `Retry-After`: the window is fixed, so its slots free up in a
 * burst the instant it rolls.
 *
 * Callers need `test.setTimeout(150_000)` — the default 60s test timeout is shorter than the
 * limiter's own 60s window, so a test that starts on an exhausted window cannot outlast it.
 */
export async function seedAdminPastRateLimit(
  request: import('@playwright/test').APIRequestContext
): Promise<import('@playwright/test').APIResponse> {
  const deadline = Date.now() + 90_000;
  let res = await request.post('/auth/seed-admin');
  while (res.status() === 429 && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 2_000));
    res = await request.post('/auth/seed-admin');
  }
  if (res.ok()) seeded = true;
  return res;
}

/**
 * Ensure workflow tables exist (for testing)
 * NOTE: This function should be called AFTER login, as it requires authentication
 */
export async function ensureWorkflowTablesExist(page: Page) {
  try {
    // Make an authenticated request using the page's cookies
    const csrfToken = await getCsrfTokenFromPage(page);
    const response = await page.request.post('/admin/api/migrations/run', {
      headers: {
        'Content-Type': 'application/json',
        ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {})
      }
    });

    // 409 means migrations are intentionally managed by Wrangler/D1.
    if (response.status() !== 404 && response.status() !== 401 && response.status() !== 409) {
      console.log('Migration response status:', response.status());
    }
  } catch (error) {
    // Migration might already be applied or endpoint not available, ignore errors
    // Don't log to reduce test output noise
  }
}

/**
 * Ensure workflow plugin is active (for testing workflow features)
 */
export async function ensureWorkflowPluginActive(page: Page) {
  // SKIP: Workflow plugin not currently installed - this function just adds overhead
  // Re-enable when workflow plugin is available
  return;
  
  /* Disabled for now - workflow plugin not installed
  try {
    const currentUrl = page.url();
    
    // Navigate to plugins page with longer timeout for CI
    await page.goto('/admin/plugins', { timeout: 20000 });
    await page.waitForLoadState('networkidle', { timeout: 15000 });
    
    // Look for workflow plugin row
    const workflowRow = page.locator('tr').filter({ hasText: 'Workflow Management' });
    const hasWorkflowPlugin = await workflowRow.count() > 0;
    
    if (hasWorkflowPlugin) {
      // Check if it's already active
      const isActive = await workflowRow.locator('.bg-green-100').count() > 0;
      
      if (!isActive) {
        // Activate the plugin
        const activateButton = workflowRow.locator('button').filter({ hasText: 'Activate' });
        if (await activateButton.count() > 0) {
          await activateButton.click();
          await page.waitForTimeout(2000); // Wait for activation
          console.log('Workflow plugin activated');
        }
      } else {
        console.log('Workflow plugin already active');
      }
    } else {
      console.log('Workflow plugin not found - may need to be installed first');
    }
    
    // Return to the original URL if it was an admin page
    if (currentUrl.includes('/admin') && !currentUrl.includes('/admin/plugins')) {
      await page.goto(currentUrl, { timeout: 20000 });
      await page.waitForLoadState('networkidle', { timeout: 15000 });
    }
  } catch (error) {
    console.log('Could not ensure workflow plugin is active:', error);
  }
  */
}

/**
 * Install + activate a plugin so its admin menu entry is rendered.
 *
 * Only `core-auth`, `core-media` and `lexical-editor` are bootstrapped on a greenfield install
 * (`PluginBootstrapService.BOOTSTRAP_PLUGIN_IDS`), and `reconcileMenuFromPlugins` hides the
 * `menu_item` row of every plugin that is not active. So a spec that asserts on a plugin's
 * sidebar link has to put the plugin in that state itself rather than inheriting it from a
 * long-lived dev database.
 *
 * Caller must already be logged in as admin — `page.request` shares the page's cookie jar.
 */
export async function ensurePluginActive(page: Page, pluginId: string): Promise<boolean> {
  return setPluginStatus(page, pluginId, 'active')
}

/**
 * Install a plugin, then leave it in the requested status.
 *
 * Counterpart of {@link ensurePluginActive} — `'inactive'` is what a spec needs when it
 * asserts on the "Inactive" status filter, whose checkbox renders `disabled` while the
 * count for that status is zero.
 */
export async function setPluginStatus(
  page: Page,
  pluginId: string,
  status: 'active' | 'inactive'
): Promise<boolean> {
  try {
    // Install first. This 200s on a fresh install and on a re-install; a non-ok response
    // only means the plugin isn't in the registry, in which case the status call below
    // fails too and the helper reports false.
    await page.request.post('/admin/plugins/install', {
      data: { name: pluginId, id: pluginId },
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
    })

    // Always run the status call even when the row already existed — it is also what
    // refreshes the plugin's `menu_item` visibility via reconcileMenuFromPlugins().
    const action = status === 'active' ? 'activate' : 'deactivate'
    const res = await page.request.post(
      `/admin/plugins/${encodeURIComponent(pluginId)}/${action}`,
      { headers: { Origin: TEST_ORIGIN } }
    )
    return res.ok()
  } catch {
    return false
  }
}

/**
 * Create test workflow content (assumes user is already logged in)
 */
export async function createTestWorkflowContent(page: Page) {
  try {
    // Ensure we have a collection first
    await ensureTestCollectionExists(page);
    
    // Navigate to content creation
    await page.goto('/admin/content/new');
    
    // Wait for the page to load and check if modelName select exists
    try {
      await page.waitForSelector('select[name="modelName"]', { timeout: 5000 });
      const models = await page.locator('select[name="modelName"] option').count();
      
      if (models > 1) { // Skip the first placeholder option
        await page.selectOption('select[name="modelName"]', { index: 1 });
        
        // Wait for dynamic fields to load
        await page.waitForTimeout(1000);
        
        await page.fill('input[name="title"]', 'Workflow Transition Test');
        await page.fill('input[name="slug"]', 'workflow-transition-test');
        await page.fill('textarea[name="content"]', 'Test content for workflow transitions.');
        
        // Submit the form
        await page.click('button[type="submit"]');
        
        // Wait for success response
        await page.waitForTimeout(2000);
      } else {
        console.log('No models available for content creation');
      }
    } catch (selectorError) {
      console.log('Model selector not found or content creation not available');
    }
  } catch (error) {
    // Content might already exist, ignore errors
    console.log('Test content creation failed:', error);
  }
}

/**
 * Ensure test content exists for content management tests
 */
export async function ensureTestContentExists(page: Page) {
  try {
    // Navigate to content list to check if content exists
    await page.goto('/admin/content/');
    await page.waitForTimeout(1000);
    
    // Check if there's already content
    const table = page.locator('table');
    const hasTable = await table.count() > 0;
    
    if (hasTable) {
      const contentRows = page.locator('tbody tr');
      const rowCount = await contentRows.count();
      
      if (rowCount > 0) {
        // Content already exists
        console.log('Test content already exists');
        return;
      }
    }
    
    // No content exists, try to create individual test content using existing collections
    console.log('Creating test content...');
    const created = await createTestContent(page, {
      title: 'Test Article for E2E Testing',
      slug: 'test-article-e2e-testing',
      content: 'This is a test article created for E2E testing purposes. It contains sample content to verify that the content management system is working correctly.'
    });
    
    if (created) {
      console.log('Successfully created test content');
    } else {
      console.log('Could not create test content - this is expected if no collections exist');
    }
    
  } catch (error) {
    console.log('Could not ensure test content exists:', error);
  }
}

/**
 * Create test content (assumes user is already logged in)
 */
export async function createTestContent(page: Page, contentData?: {
  title: string;
  slug: string;
  content: string;
}) {
  const data = contentData || {
    title: 'Test Content',
    slug: 'test-content',
    content: 'This is test content for E2E testing.'
  };

  try {
    // Ensure we have a collection first
    await ensureTestCollectionExists(page);
    
    // Navigate to content creation
    await page.goto('/admin/content/new');
    
    // Check if we get the collection selection page
    try {
      // Look for collection cards (new UI)
      await page.waitForSelector('.collection-card, .grid', { timeout: 5000 });
      
      // Click on the first available collection
      const collectionLinks = page.locator('a[href*="/admin/content/new?collection="]');
      const collectionCount = await collectionLinks.count();
      
      if (collectionCount > 0) {
        await collectionLinks.first().click();
        
        // Wait for the form to load
        await page.waitForTimeout(2000);
        
        // Fill in the form fields - try different possible field names
        const titleField = page.locator('input[name="title"], input[name="name"], input[id="title"]').first();
        if (await titleField.count() > 0) {
          await titleField.fill(data.title);
        }
        
        const slugField = page.locator('input[name="slug"], input[id="slug"]').first();
        if (await slugField.count() > 0) {
          await slugField.fill(data.slug);
        }
        
        const contentField = page.locator('textarea[name="content"], textarea[name="body"], textarea[id="content"]').first();
        if (await contentField.count() > 0) {
          await contentField.fill(data.content);
        }
        
        // Submit the form
        const submitButton = page.locator('button[type="submit"], input[type="submit"]').first();
        if (await submitButton.count() > 0) {
          await submitButton.click();
          
          // Wait for form submission
          await page.waitForTimeout(2000);
          return true;
        }
      }
    } catch (selectionError) {
      // Fall back to old model-based approach
      await page.waitForSelector('select[name="modelName"]', { timeout: 5000 });
      const models = await page.locator('select[name="modelName"] option').count();
      
      if (models > 1) {
        await page.selectOption('select[name="modelName"]', { index: 1 });
        
        // Wait for dynamic fields to load
        await page.waitForTimeout(1500);
        
        // Fill in the form fields
        await page.fill('input[name="title"]', data.title);
        await page.fill('input[name="slug"]', data.slug);
        await page.fill('textarea[name="content"]', data.content);
        
        // Submit the form
        await page.click('button[type="submit"]');
        await page.waitForTimeout(2000);
        return true;
      }
    }
    
    console.log('No collections or models available for content creation');
    return false;
  } catch (error) {
    console.log('Test content creation failed:', error);
    return false;
  }
}

/**
 * Ensure test collection exists
 */
export async function ensureTestCollectionExists(_page: Page) {
  // Collections are code-only now (no DB table, no creation UI — see drop-db-collections plan).
  // The seeded `blog_post` collection always exists, so there is nothing to create. This is a no-op;
  // the old version drove /admin/collections/new (which is now instructional), hanging for ~60s
  // and timing out every caller (createTestContent → 05/11/12/42 cascades).
  return;
}

/**
 * Fill and submit the /auth/login form, waiting out a rate-limit rejection instead of failing on it.
 *
 * `/auth/login/form` is capped at 30 requests per minute per IP and the whole suite is one IP —
 * on a workers.dev preview `cf-connecting-ip` is the single CI runner, and on a local dev server
 * there is no IP header at all so every worker shares the `unknown` bucket. Four workers running
 * specs that each sign a throwaway user in blow that bucket in a burst. The 429 comes back to an
 * htmx post, which does not swap non-2xx responses, so the page simply does not move and the test
 * reports a bare `waitForURL` timeout with nothing on screen to explain it.
 *
 * The limit itself is correct — brute-force protection should not be weakened to suit a test
 * suite — so this waits for the window to roll and submits again. The wait is not the test's own
 * work, so its budget is extended by however long it queued.
 */
/**
 * Hand back time spent queueing behind someone else's rate-limit window.
 *
 * Waiting for a bucket to drain is not the test's own work, so it should not come out of the
 * test's budget. No-op when there is no running test: `test.info()` throws inside a `beforeAll`
 * hook, which is one of the places the callers below run from.
 */
function extendCurrentTimeout(ms: number) {
  try {
    const info = test.info();
    info.setTimeout(info.timeout + ms);
  } catch {
    // beforeAll/afterAll — the hook's budget is the test timeout and cannot be extended here.
  }
}

/**
 * POST /auth/login and return the bearer token, waiting out a rate-limit rejection.
 *
 * `/auth/login` is capped at 30 requests per minute per IP and the whole suite is one IP: on a
 * workers.dev preview `cf-connecting-ip` is the single CI runner, and against a local dev server
 * there is no IP header at all so every worker shares the `unknown` bucket. 02b-authentication-api
 * deliberately empties that bucket to prove the limiter works.
 *
 * The `@lock-auth-login` tag keeps those tests from overlapping, but it is a *test-scoped* fixture
 * and a `beforeAll` hook runs before any test's fixtures are set up — so hooks are not covered by
 * it. That is exactly where 16-user-management's admin login came back 429, leaving `authToken`
 * undefined and every test in the file failing on a DELETE that was never authorised.
 *
 * The limit itself is correct — brute-force protection should not be weakened to suit a test
 * suite — so wait for the window to roll and ask again.
 */
export async function requestLoginToken(
  request: APIRequestContext,
  credentials: { email: string; password: string } = ADMIN_CREDENTIALS
): Promise<string> {
  const MAX_ATTEMPTS = 3;
  /** The window is 60s wide, so no legitimate Retry-After exceeds it. */
  const MAX_BACKOFF_MS = 65_000;

  let res = await request.post('/auth/login', { data: credentials });
  for (let attempt = 1; res.status() === 429 && attempt < MAX_ATTEMPTS; attempt++) {
    const retryAfter = Number(res.headers()['retry-after'] ?? '60');
    const backoff = Math.min(Number.isFinite(retryAfter) ? retryAfter * 1000 : 60_000, MAX_BACKOFF_MS);
    extendCurrentTimeout(backoff + 10_000);
    await new Promise((resolve) => setTimeout(resolve, backoff + 500));
    res = await request.post('/auth/login', { data: credentials });
  }

  expect(res.status(), `/auth/login failed: ${await res.text()}`).toBe(200);
  const body = await res.json();
  expect(typeof body.token, '/auth/login returned 200 without a token').toBe('string');
  return body.token as string;
}

export async function submitLoginForm(
  page: Page,
  email: string,
  password: string,
  expectUrl: RegExp = /\/admin/,
  timeout = 20000
) {
  const MAX_ATTEMPTS = 3
  /** The window is 60s wide, so no legitimate Retry-After exceeds it. */
  const MAX_BACKOFF_MS = 65_000

  for (let attempt = 1; ; attempt++) {
    await page.fill('input[name="email"]', email)
    await page.fill('input[name="password"]', password)

    const posted = page.waitForResponse(
      (r) => r.url().includes('/auth/login/form') && r.request().method() === 'POST',
      { timeout }
    )
    await page.click('button[type="submit"]')
    const res = await posted

    if (res.status() !== 429 || attempt === MAX_ATTEMPTS) break

    const retryAfter = Number(res.headers()['retry-after'] ?? '60')
    const backoff = Math.min(Number.isFinite(retryAfter) ? retryAfter * 1000 : 60_000, MAX_BACKOFF_MS)
    extendCurrentTimeout(backoff + 10_000)
    await page.waitForTimeout(backoff + 500)
    await page.reload({ waitUntil: 'domcontentloaded' })
  }

  await page.waitForURL(expectUrl, { timeout, waitUntil: 'domcontentloaded' })
}

/**
 * Login as admin user.
 *
 * `landOn` picks the page the browser is left on. The default `/admin` is the dashboard, which
 * fans out into four htmx fragments and is the single most expensive page in the app to render
 * cold. A spec whose first act is to navigate somewhere else pays that for nothing — and four
 * parallel workers all cold-starting the dashboard at once is what pushed the media specs past
 * their 90s budget. Pass the page the spec actually wants, or `false` to stay put (the session
 * cookie is already in the context either way, since sign-in goes through `page.request`).
 */
/**
 * The admin session this worker process has already paid for.
 *
 * Measured against the app: `POST /auth/sign-in/email` is 42ms on its own, but eight concurrent
 * sign-ins each take 315ms and all finish together at ~8x40ms — the password verification
 * serializes in the isolate rather than overlapping. Every test in the suite signed in from
 * scratch, so a CI run was ~530 serialized hashes from four workers against one preview isolate,
 * and that is what the 120s hangs were: `beforeEach` queued behind other workers' scrypt. The
 * hangs showed up on `apiRequestContext.post` as often as on `page.goto`, with no browser in the
 * loop, which is what ruled out the renderer and pointed here.
 *
 * `GET /auth/get-session` with an existing cookie is 4ms and does no hashing, so it does not
 * serialize. Sign in once per worker; re-validate with that instead.
 */
type SessionCookies = Awaited<ReturnType<BrowserContext['cookies']>>
let cachedSessionCookies: SessionCookies | null = null

/** The email the cookie jar currently authenticates as, lowercased, or null if nobody. */
async function signedInAs(page: Page): Promise<string | null> {
  const res = await page.request
    .get('/auth/get-session', { headers: { Origin: TEST_ORIGIN } })
    .catch(() => null)
  if (!res || !res.ok()) return null
  const body = (await res.json().catch(() => null)) as { user?: { email?: string } } | null
  return body?.user?.email?.toLowerCase() ?? null
}

/**
 * Install the cached session into this test's context and prove it is live *and the admin's*.
 *
 * Validated with a request, not with "did a navigation land on /auth/login": `loginAsAdmin(page,
 * false)` callers never navigate, so a revoked session would otherwise go unnoticed until some
 * later step failed for an unrelated-looking reason. Specs that sign out, reset a password or
 * enrol a second factor on the shared admin all revoke the session — this is the path that
 * notices and falls back to a real sign-in.
 *
 * Checking the identity, not just that `user` is present, is the whole point. `loginAsAdmin` is
 * not only called from a `beforeEach` with a fresh context: specs sign in as somebody else first
 * and then call it to get back to being admin. `108-two-factor-api-enforcement` does exactly
 * that — `createEnrolledUser` signs in as a throwaway user and enrols them, then `resetAsAdmin`
 * calls `loginAsAdmin`. That user's `better-auth.session_token` is still in the jar, it is live,
 * and it has a `user`, so a presence-only check reports success and the real sign-in is skipped.
 * The page then stays authenticated as the wrong person, `/admin` redirects away from itself,
 * and `loginAsAdmin`'s `waitForURL(/\/admin/)` times out at 20s on both attempts. That was three
 * hard failures in CI run 39587538658, plus the RBAC and auth specs that do the same thing.
 *
 * When the jar holds a foreign session, clear it and retry with only the cached cookies before
 * giving up — the admin session is usually still perfectly good, just shadowed. Cookies are
 * cleared only on that path, so the ordinary `beforeEach` case still touches nothing.
 */
async function reuseCachedSession(page: Page): Promise<boolean> {
  if (!cachedSessionCookies) return false

  const adminEmail = ADMIN_CREDENTIALS.email.toLowerCase()

  await page.context().addCookies(cachedSessionCookies)
  if ((await signedInAs(page)) === adminEmail) return true

  // Either nobody is signed in, or somebody else's cookie won. Drop everything and re-seat only
  // the cached admin cookies — `addCookies` does not reliably displace a same-named cookie that
  // another sign-in set with a different path or domain.
  await page.context().clearCookies()
  await page.context().addCookies(cachedSessionCookies)
  if ((await signedInAs(page)) === adminEmail) return true

  // The cached session itself is dead (signed out, password changed, second factor enrolled).
  cachedSessionCookies = null
  await page.context().clearCookies()
  return false
}

export async function loginAsAdmin(page: Page, landOn: string | false = '/admin') {
  if (!(await reuseCachedSession(page))) {
    await signInAsAdmin(page);
  }

  // Navigate to admin (session cookie is now in context).
  //
  // `domcontentloaded`, not the default `load`: this runs in almost every spec's beforeEach, and
  // /admin is the heaviest page in the app (metrics + recent activity + migrations status all
  // polling). Waiting for it to go quiet can eat most of the 60s test budget before the test
  // body starts. Nothing here needs subresources — the caller's own assertions auto-wait.
  if (landOn !== false) {
    await page.goto(landOn, { waitUntil: 'domcontentloaded' });
    await page.waitForURL(/\/admin/, { timeout: 20000, waitUntil: 'domcontentloaded' });
  }

  // No `ensureWorkflowTablesExist` / `ensureWorkflowPluginActive` here. The first POSTs
  // /admin/api/migrations/run, which on D1 always answers 409 ("Migrations are managed by
  // Cloudflare D1") — a guaranteed-useless round trip in the beforeEach of nearly every spec. The
  // second has been a bare `return` since the workflow plugin stopped shipping. The three specs
  // that actually care (15-plugins, 28-plugin-filters-search, 39-ai-search-plugin) call
  // ensureWorkflowTablesExist themselves.
}

/** The real sign-in: seed, hash a password, keep the cookies it issued. */
async function signInAsAdmin(page: Page) {
  // Ensure admin exists (also creates auth_account for Better Auth)
  await ensureAdminUserExists(page);

  // Use Better Auth's sign-in/email API — sets session cookie in the page context.
  // Retry on 5xx OR network timeout: preview CF Worker cold-starts can return 500
  // transiently or time-out during bootstrap under parallel worker load.
  const signInAttempt = () =>
    page.request.post('/auth/sign-in/email', {
      data: { email: ADMIN_CREDENTIALS.email, password: ADMIN_CREDENTIALS.password },
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
      timeout: 45_000,
    });

  let res = await signInAttempt().catch(() => null);
  if (!res || (!res.ok() && res.status() >= 500)) {
    await page.waitForTimeout(3000);
    res = await signInAttempt().catch(() => null);
  }
  if (!res || (!res.ok() && res.status() >= 500)) {
    await page.waitForTimeout(5000);
    res = await signInAttempt().catch(() => null);
  }
  if (!res || (!res.ok() && res.status() >= 500)) {
    await page.waitForTimeout(8000);
    res = await signInAttempt();
  }

  if (!res.ok()) {
    throw new Error(`BA sign-in failed: ${res.status()} ${await res.text()}`);
  }

  // A pending second factor is HTTP **200** with `{twoFactorRedirect:true}` and NO session, so
  // `res.ok()` above does not catch it. Without this check the failure surfaces as a 20-second
  // waitForURL timeout in whatever spec happens to run next — which is what a 2FA spec that died
  // before its cleanup would leave behind on the shared admin account.
  const body = (await res.json().catch(() => null)) as { twoFactorRedirect?: boolean } | null;
  if (body?.twoFactorRedirect === true) {
    throw new Error(
      'BA sign-in returned a two-factor challenge for the shared admin account: no session was ' +
        'issued. A 2FA spec probably failed before disabling it — clear auth_two_factor for ' +
        `${ADMIN_CREDENTIALS.email} and reset auth_user.two_factor_enabled to 0.`
    );
  }

  // Keep only what the sign-in issued. `context.cookies()` also holds `csrf_token`, which the
  // app rotates per request and `getCsrfTokenFromPage` reads straight back out of the jar —
  // replaying a stale one into 700 later contexts is a risk the session token does not carry.
  // Confirm the jar actually authenticates as the admin before caching it for the rest of the
  // worker. A spec that signed in as somebody else first can leave their own `better-auth.*`
  // cookie behind on a different path, and caching that would poison every later test in the
  // process — the same failure as reusing a foreign session, but persistent instead of per-test.
  //
  // Self-healing rather than fatal: on a worker's first call `reuseCachedSession` returns before
  // it clears anything, so a foreign cookie can still be present here. Clearing and signing in
  // again on a clean jar settles it.
  if ((await signedInAs(page)) !== ADMIN_CREDENTIALS.email.toLowerCase()) {
    await page.context().clearCookies();
    const retry = await page.request.post('/auth/sign-in/email', {
      data: { email: ADMIN_CREDENTIALS.email, password: ADMIN_CREDENTIALS.password },
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
      timeout: 45_000,
    }).catch(async () => {
      // Timeout on retry — wait and try once more before giving up
      await page.waitForTimeout(5000);
      return page.request.post('/auth/sign-in/email', {
        data: { email: ADMIN_CREDENTIALS.email, password: ADMIN_CREDENTIALS.password },
        headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
        timeout: 45_000,
      });
    });
    if (!retry.ok()) {
      throw new Error(`BA sign-in failed on a cleared jar: ${retry.status()} ${await retry.text()}`);
    }
    if ((await signedInAs(page)) !== ADMIN_CREDENTIALS.email.toLowerCase()) {
      cachedSessionCookies = null;
      throw new Error(
        'Signed in as the admin but /auth/get-session reports somebody else, on a jar that was ' +
          'just cleared. The shared admin account is in an unexpected state.'
      );
    }
  }

  // Match the name anywhere, not as a prefix. Better Auth adds the `__Secure-` cookie prefix when
  // it is serving over HTTPS, so the session cookie is `better-auth.session_token` against a local
  // wrangler but `__Secure-better-auth.session_token` against the CI preview deployment. A
  // `startsWith` filter therefore captured the real cookies locally and an EMPTY array in CI — the
  // cache silently did nothing in the only environment it was written for, and cost two extra
  // /auth/get-session round trips per test on top of the sign-in it failed to avoid.
  const all = await page.context().cookies();
  const session = all.filter((c) => c.name.includes('better-auth.'));

  // An empty list is not a cache. Leaving it null makes the next call sign in directly rather than
  // walk `reuseCachedSession`'s clear-and-recheck path to discover the same thing again.
  cachedSessionCookies = session.length > 0 ? session : null;
}

/**
 * Open the media library and wait for its grid.
 *
 * Use this instead of `page.goto('/admin/media')`. `goto` defaults to `waitUntil: 'load'`, which
 * holds until every thumbnail in the grid has answered. Thumbnails are served by the worker out
 * of R2 and workers.dev previews get no edge cache, so each is a ~0.8s round trip: a default
 * `goto` here measured 12.6s against a preview where the HTML alone took 2.2s. Three media specs
 * were blowing their 90s budget on that wait alone once four workers competed for the isolate.
 *
 * `#media-grid` is server-rendered in the page body — it holds either the grid or the empty
 * state — so it is present the moment the document parses. Nothing is being raced here; the wait
 * is a guard that we landed on the library and not a redirect to the login page.
 */
export async function gotoMediaLibrary(page: Page, url = '/admin/media') {
  await page.goto(url, { waitUntil: 'domcontentloaded' });
  await page.locator('#media-grid').waitFor({ state: 'attached', timeout: 20000 });
}

/**
 * Navigate to a specific admin section
 */
export async function navigateToAdminSection(page: Page, section: 'collections' | 'content' | 'media' | 'users' | 'forms' | 'plugins') {
  // Navigate directly instead of clicking navigation links
  // This is more reliable as admin navigation may vary
  await page.goto(`/admin/${section}`, { waitUntil: 'domcontentloaded' });
  await page.waitForURL(/\/admin/, { timeout: 20000, waitUntil: 'domcontentloaded' });
}

/**
 * Create a test collection
 */
export async function createTestCollection(page: Page, collectionData = TEST_DATA.collection) {
  await navigateToAdminSection(page, 'collections');
  await page.click('a[href="/admin/collections/new"]');

  await page.fill('[name="name"]', collectionData.name);
  await page.fill('[name="displayName"]', collectionData.displayName);
  await page.fill('[name="description"]', collectionData.description);

  await page.click('button[type="submit"]');

  // Wait for form submission - either redirect or manually navigate
  try {
    await page.waitForURL('/admin/collections', { timeout: 10000 });
  } catch {
    // If no automatic redirect, navigate manually
    await page.goto('/admin/collections');
  }

  // Wait for database write and any caching to settle
  await page.waitForTimeout(2000);
}

/**
 * Delete a test collection
 */
export async function deleteTestCollection(page: Page, collectionName: string) {
  try {
    await navigateToAdminSection(page, 'collections');

    // Check if collection exists
    const collectionRow = page.locator('tr').filter({ hasText: collectionName });
    const isVisible = await collectionRow.isVisible({ timeout: 2000 });

    if (!isVisible) {
      // Collection doesn't exist, nothing to delete
      return;
    }

    // Click the row itself (rows are clickable for editing)
    await collectionRow.click();

    // Wait for edit page to load
    await page.waitForTimeout(1000);

    // Set up dialog handler before clicking delete (use once to avoid handler accumulation)
    page.once('dialog', dialog => dialog.accept());

    // Click delete button
    await page.locator('button').filter({ hasText: 'Delete Collection' }).click();

    // Wait for redirect back to collections list (shorter timeout for cleanup)
    try {
      await page.waitForURL('/admin/collections', { timeout: 5000 });
    } catch {
      // If didn't redirect, navigate manually
      await page.goto('/admin/collections');
    }
  } catch (error) {
    // If deletion fails, just continue - this is cleanup, don't log noise
    // Silent failure for cleanup operations
  }
}

/**
 * Upload a test file
 */
export async function uploadTestFile(page: Page, fileName: string = 'test-image.jpg') {
  await navigateToAdminSection(page, 'media');
  await page.locator('button').filter({ hasText: 'Upload Files' }).click();
  
  // Create a test file buffer (1x1 pixel JPEG)
  const testImageBuffer = Buffer.from([
    0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
    0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
    0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
    0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
    0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20,
    0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29,
    0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
    0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x11, 0x08, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01,
    0xFF, 0xC4, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0xFF, 0xC4,
    0x00, 0x14, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xDA, 0x00, 0x0C,
    0x03, 0x01, 0x00, 0x02, 0x11, 0x03, 0x11, 0x00, 0x3F, 0x00, 0x80, 0xFF, 0xD9
  ]);
  
  // Set the file to upload
  await page.setInputFiles('#file-input', {
    name: fileName,
    mimeType: 'image/jpeg',
    buffer: testImageBuffer
  });
  
  // Same as the spec-level upload sites: #upload-results is rendered from the POST response,
  // so the default assertion budget would be standing in for an R2 write. Await the response.
  await submitAndWaitForXhr(page, 'POST', '/admin/media/upload', () =>
    page.click('button[type="submit"]')
  );

  await expect(page.locator('#upload-results')).toContainText('successful');
}

/**
 * Wait for any in-flight HTMX request to finish.
 *
 * htmx puts the `htmx-request` class on the element issuing the request (and on any
 * `hx-indicator`) for exactly the lifetime of that request, so that class is the signal. The
 * version this replaces waited on `networkidle` for 5s and then, on timeout, slept another
 * second — and admin pages poll metrics, recent activity and migration status, so they do not go
 * idle and every one of the 19 call sites paid the full 6s whether or not anything was pending.
 *
 * Returns within a frame when nothing is in flight, which is the common case: a request that has
 * not been issued yet marks nothing, and every caller follows this with an auto-waiting
 * assertion (`toHaveURL`, `toBeVisible`, `toContainText`) that does the real waiting. Kept
 * best-effort — the timeout is swallowed, as it was before, because the caller's assertion is
 * what should report a swap that never happened, and a click that navigates tears down the
 * execution context under `waitForFunction`.
 */
export async function waitForHTMX(page: Page) {
  await page
    .waitForFunction(() => !document.querySelector('.htmx-request'), null, { timeout: 5000 })
    .catch(() => {});
}

/**
 * Check if user is authenticated by checking for auth cookie
 */
export async function isAuthenticated(page: Page): Promise<boolean> {
  try {
    // Check server-side session rather than local cookies — more reliable across
    // cookie attribute differences (HttpOnly, Secure, SameSite) in CI vs local.
    const res = await page.request.get('/auth/get-session')
    if (!res.ok()) return false
    const body = await res.json().catch(() => null)
    return !!(body?.user)
  } catch {
    return false
  }
}

/**
 * Logout current user
 */
export async function logout(page: Page) {
  // Better Auth sign-out via API — must send JSON body {}
  await page.request.post('/auth/sign-out', { data: {}, headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN } });
  await page.goto('/auth/login');
  await page.waitForURL(/\/auth\/login/);
  // Wait a moment for cookies to be cleared
  await page.waitForTimeout(500);
}

/**
 * Clear test data - comprehensive database cleanup
 */
export async function clearTestData(page: Page) {
  try {
    // Use public API to clean up test data (no auth required)
    const response = await page.request.post('/test-cleanup', {
      headers: {
        'Content-Type': 'application/json'
      }
    });

    if (response.ok()) {
      console.log('Test data cleanup successful');
    } else {
      console.log('Test data cleanup failed:', response.status());
    }
  } catch (error) {
    // If API endpoint doesn't exist or fails, try UI-based cleanup
    console.log('API cleanup failed, attempting UI cleanup:', error);
    try {
      await loginAsAdmin(page);

      // Delete test collections
      try {
        await deleteTestCollection(page, TEST_DATA.collection.name);
        await deleteTestCollection(page, 'test_collection_e2e');
        await deleteTestCollection(page, 'test_articles');
      } catch {
        // Collections might not exist
      }

      await logout(page);
    } catch {
      // Ignore cleanup errors
    }
  }
}

/**
 * Clean up test users (but preserve admin)
 *
 * `testCleanupRoutes` is mounted at the ROOT in app.ts, so the path is `/test-cleanup/users` —
 * this previously posted to `/admin/api/test-cleanup/users`, which has never existed, so the
 * request 404'd and the swallowed-error `catch` made it look like a successful sweep.
 */
export async function cleanupTestUsers(page: Page) {
  try {
    const res = await page.request.post('/test-cleanup/users');
    if (!res.ok()) console.log(`User cleanup returned ${res.status()}`);
  } catch (error) {
    console.log('User cleanup failed:', error);
  }
}

/**
 * Returns a beforeAll/beforeEach pair that skips all tests in the suite when a route is 404.
 * Usage at top of plugin spec:
 *
 *   let featureAvailable = false
 *   test.beforeAll(async ({ request }) => { featureAvailable = await isFeatureAvailable(request, '/admin/cache') })
 *   test.beforeEach(() => { test.skip(!featureAvailable, 'Plugin not installed in this deployment') })
 */
export async function isFeatureAvailable(request: import('@playwright/test').APIRequestContext, route: string): Promise<boolean> {
  try {
    const baseURL = process.env.BASE_URL || 'http://localhost:8787'
    // Authenticate so that auth-protected admin routes return 200/404 rather than 302→login.
    // Without auth, all /admin/* routes redirect to /auth/login (not 404), making it impossible
    // to distinguish "plugin not installed" from "plugin installed but needs auth".
    await seedAdminOnce(request)
    await request.post('/auth/sign-in/email', {
      data: { email: ADMIN_CREDENTIALS.email, password: ADMIN_CREDENTIALS.password },
      headers: { 'Content-Type': 'application/json', Origin: baseURL },
    }).catch(() => {})
    const res = await request.get(route)
    // Only 2xx means the feature exists and is accessible. 401/403 mean auth failed
    // (sign-in silently errored) — treat as unavailable, not as "feature present".
    return res.ok()
  } catch {
    return false
  }
}

/**
 * Check API health
 */
export async function checkAPIHealth(page: Page) {
  const response = await page.request.get('/health');
  expect(response.ok()).toBeTruthy();
  const health = await response.json();
  expect(health.status).toBe('running');
  return health;
}

/* ──────────────────────────────────────────────────────────────────────────────
 * Rich text fields
 *
 * `renderDynamicField` decides SERVER-SIDE which editor backs a rich text field, and the
 * markup it emits is different in every case — there is no single selector that works:
 *
 *   lexical  (the default on a fresh install, when the lexical-editor plugin is active)
 *            `.lexical-editor-wrapper` → contenteditable surface + `<input type="hidden">`
 *   tinymce  `.richtext-container[data-editor-provider="tinymce"]` wrapping a `<textarea>`
 *   easymde  `.richtext-container[data-editor-provider="easymde"]` wrapping a `<textarea>`
 *   quill    `.quill-editor-container` → contenteditable div + hidden input
 *   textarea no editor plugin active at all → amber-bannered plain `<textarea>`
 *
 * Specs used to assume a binary ("the editor under test, or else a plain textarea"), which
 * is wrong the moment a *different* editor owns the field: on a fresh install Lexical does,
 * so `textarea[name="content"]` does not exist at all. Route rich text through these helpers
 * instead of hard-coding a selector.
 * ────────────────────────────────────────────────────────────────────────────── */

export type RichTextBacking = 'lexical' | 'tinymce' | 'easymde' | 'quill' | 'textarea' | 'missing';

/** Which editor the server actually rendered for `fieldName` on the current page. */
export async function richTextBacking(page: Page, fieldName: string): Promise<RichTextBacking> {
  if (await page.locator(`.lexical-editor-wrapper:has(input[name="${fieldName}"])`).count() > 0) return 'lexical';
  if (await page.locator(`.richtext-container[data-editor-provider="tinymce"]:has(textarea[name="${fieldName}"])`).count() > 0) return 'tinymce';
  if (await page.locator(`.richtext-container[data-editor-provider="easymde"]:has(textarea[name="${fieldName}"])`).count() > 0) return 'easymde';
  if (await page.locator(`.quill-editor-container:has(input[name="${fieldName}"]), .quill-editor-container:has(textarea[name="${fieldName}"])`).count() > 0) return 'quill';
  if (await page.locator(`textarea[name="${fieldName}"]`).count() > 0) return 'textarea';
  return 'missing';
}

/**
 * The element a user actually types into for `fieldName`, whichever editor backs it.
 * For the textarea backings this is the form control itself; for Lexical/Quill it is the
 * contenteditable surface, and the form control is a sibling hidden input.
 */
export function richTextSurface(page: Page, fieldName: string, backing: RichTextBacking) {
  switch (backing) {
    case 'lexical':
      return page.locator(`.lexical-editor-wrapper:has(input[name="${fieldName}"]) .lexical-content-editable`).first();
    case 'quill':
      return page.locator('.quill-editor-container .ql-editor, .quill-editor-container .quill-editor').first();
    case 'easymde':
      // EasyMDE hides the textarea behind CodeMirror once it hydrates; before that the
      // textarea is still the surface.
      return page.locator(`.CodeMirror, textarea[name="${fieldName}"]`).first();
    default:
      return page.locator(`textarea[name="${fieldName}"]`).first();
  }
}

/**
 * Put `value` into a rich text field through whichever editor rendered.
 *
 * Lexical only mirrors into its hidden input from an editor update listener, so typing is the
 * only way to get a value that survives submit — unless the CDN bundle never loaded, in which
 * case nothing will overwrite a value written straight to the hidden input.
 * Returns the backing that was used so callers can assert against the right surface.
 */
export async function fillRichTextField(page: Page, fieldName: string, value: string): Promise<RichTextBacking> {
  const backing = await richTextBacking(page, fieldName);

  if (backing === 'lexical') {
    const wrapper = page.locator(`.lexical-editor-wrapper:has(input[name="${fieldName}"])`).first();
    const initialized = await wrapper
      .evaluate((el) => el.getAttribute('data-lexical-initialized') === 'true')
      .catch(() => false);

    if (!initialized) {
      await page
        .waitForFunction(
          (name) => {
            const w = document.querySelector(`.lexical-editor-wrapper:has(input[name="${name}"])`);
            return !!w && w.getAttribute('data-lexical-initialized') === 'true';
          },
          fieldName,
          { timeout: 15000 }
        )
        .catch(() => {});
    }

    const ready = await wrapper
      .evaluate((el) => el.getAttribute('data-lexical-initialized') === 'true')
      .catch(() => false);

    if (ready) {
      const surface = richTextSurface(page, fieldName, backing);
      await surface.click();
      await page.keyboard.type(value);
      // The update listener is what writes the hidden input; wait for it rather than racing it.
      await expect(page.locator(`.lexical-editor-wrapper input[name="${fieldName}"]`)).not.toHaveValue('');
    } else {
      // Lexical never booted (CDN blocked): nothing will clobber a direct write.
      await page.locator(`.lexical-editor-wrapper input[name="${fieldName}"]`).evaluate((el, v) => {
        (el as HTMLInputElement).value = v;
      }, value);
    }
    return backing;
  }

  if (backing === 'quill') {
    const surface = richTextSurface(page, fieldName, backing);
    await surface.click();
    await page.keyboard.type(value);
    return backing;
  }

  if (backing === 'easymde') {
    const codeMirror = page.locator('.CodeMirror').first();
    if (await codeMirror.count() > 0) {
      await codeMirror.click();
      await page.keyboard.type(value);
      return backing;
    }
    await page.locator(`textarea[name="${fieldName}"]`).fill(value);
    return backing;
  }

  if (backing === 'textarea' || backing === 'tinymce') {
    await page.locator(`textarea[name="${fieldName}"]`).fill(value);
    return backing;
  }

  throw new Error(`No rich text field named "${fieldName}" rendered on ${page.url()}`);
}

/**
 * The value that would be submitted for `fieldName` — read off the form control, not the
 * editing surface, so it is the same string the server will receive.
 */
export async function richTextFieldValue(page: Page, fieldName: string): Promise<string> {
  return page.evaluate((name) => {
    const el = document.querySelector(
      `textarea[name="${name}"], input[name="${name}"]`
    ) as HTMLInputElement | HTMLTextAreaElement | null;
    return el?.value ?? '';
  }, fieldName);
}

/**
 * Assert the field is present and usable whichever editor backs it. Used by the per-editor
 * specs in the branch where the editor under test is NOT the one that rendered: the point is
 * that the field still works, not which editor won.
 */
export async function expectRichTextFieldUsable(page: Page, fieldName: string) {
  const backing = await richTextBacking(page, fieldName);
  expect(backing, `no rich text field named "${fieldName}" rendered`).not.toBe('missing');

  const surface = richTextSurface(page, fieldName, backing);
  await expect(surface).toBeVisible();

  if (backing === 'textarea' || backing === 'tinymce') {
    await expect(surface).toBeEditable();
  } else {
    // Contenteditable surfaces are not "editable" in the form-control sense Playwright checks.
    await expect(surface).toHaveAttribute('contenteditable', 'true');
  }

  // Whatever the surface, the form must still carry a control the save posts.
  await expect(page.locator(`textarea[name="${fieldName}"], input[name="${fieldName}"]`)).toHaveCount(1);
  return backing;
}

/**
 * Names of the rich text fields on the current page whose real form control is a *hidden*
 * input — Lexical and Quill both edit a contenteditable surface and mirror into one.
 *
 * These are invisible to the usual "fill every visible [required] control" sweep, so a form
 * that looks complete still fails server-side validation. Callers that need a submittable
 * form (rather than a specific editor's behaviour) use this to find what they missed.
 */
export async function hiddenEditorFieldNames(page: Page): Promise<string[]> {
  return page.evaluate(() =>
    Array.from(
      document.querySelectorAll(
        '.lexical-editor-wrapper input[type="hidden"][name], .quill-editor-container input[type="hidden"][name]'
      )
    )
      .map((el) => (el as HTMLInputElement).name)
      .filter(Boolean)
  );
}

/** Fill every empty hidden-input-backed rich text field on the page. Returns the names filled. */
export async function fillHiddenEditorFields(page: Page, value: string): Promise<string[]> {
  const filled: string[] = [];
  for (const name of await hiddenEditorFieldNames(page)) {
    if (await richTextFieldValue(page, name)) continue;
    await fillRichTextField(page, name, value);
    filled.push(name);
  }
  return filled;
}
