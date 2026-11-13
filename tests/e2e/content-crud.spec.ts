import { test } from "./fixtures"
import { expect } from "./fixtures"
import type { Page } from "@playwright/test"
import { loginAsAdmin } from "./utils/test-helpers"
import { saveNewContent } from "./fixtures/content-fixtures"
import { test as source5_test } from "@playwright/test"
import { expect as source6_expect } from "@playwright/test"
import { ensureAdminUserExists } from "./utils/test-helpers"
import { waitForHTMX } from "./utils/test-helpers"

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 05-content.spec.ts", () => {
  /**
   * Every test in this file used to pass without checking anything.
   *
   * Three habits did it:
   *
   * 1. `expect(hasTable || hasEmptyState).toBeTruthy()` — the content list renders a table when it
   *    has rows and an empty-state panel when it does not, so that disjunction is "the handler
   *    returned a page", which the `h1` assertion above it already proved.
   * 2. `expect(rowCount).toBeGreaterThanOrEqual(0)` — a count is never negative.
   * 3. The real assertions sat inside `if (await x.count() > 0)`. The action buttons, the select-all
   *    checkbox, the workflow dropdown and the pagination summary were all checked only when they
   *    happened to be present, so an empty list checked none of them. `should filter content by
   *    status` went further and wrapped its body in `try/catch`, falling back to "verify the page is
   *    still functional"; `should create new content` ended by logging
   *    `⚠️ Content was not created - this indicates an issue with the form submission` and passing.
   *
   * Each test now creates the record it inspects and scopes the list to it with `?search=`, so the
   * row count is exact rather than "whatever the other three workers have written so far".
   *
   * `should show workflow actions for content` is gone: it looked for a `Actions ▼` button that does
   * not exist in the template, and document-backed rows carry `availableActions: []` by design (D14 —
   * the list-level publish/unpublish endpoints are keyed by a legacy version id, not a root id).
   */

  /** `e2e_test` is code-registered and needs only title + slug; every other collection has required fields this spec does not model. */
  const NEW_RECORD_FORM = '/admin/content/new?collection=e2e_test';

  type Record = { id: string; title: string; slug: string };

  /**
   * `?model=` and `?collection=` are both accepted by the list handler, and `?search=` filters on
   * `title LIKE` in both the document-backed branch and the all-view union — which is what makes a
   * `toHaveCount(1)` assertion safe under `workers: 4`.
   */
  function searchUrl(term: string, model = 'e2e_test'): string {
    const params = new URLSearchParams({ status: 'all', search: term });
    if (model !== 'all') params.set('collection', model);
    return `/admin/content?${params.toString()}`;
  }

  async function createRecord(page: Page, label = 'List item'): Promise<Record> {
    const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const title = `${label} ${stamp}`;
    const slug = `${label.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${stamp}`;

    await page.goto(NEW_RECORD_FORM);
    await page.fill('input[name="title"]', title);
    await page.fill('input[name="slug"]', slug);
    // The handler reads `status` off the form and falls back to 'draft'. Set it explicitly so the
    // status badge and the status filter below have one expected value rather than two.
    await page.selectOption('select[name="status"]', 'draft');

    // `saveNewContent` reads the POST's HX-Redirect before waiting for htmx to navigate, so a
    // validation failure is reported as a validation failure rather than a navigation timeout.
    const editPath = await saveNewContent(page, () =>
      page.locator('button[type="submit"]').filter({ hasText: /Save|Create/ }).first().click()
    );
    return { id: editPath.split('/')[3], title, slug };
  }

  function rowFor(page: Page, record: Record) {
    return page.locator('tbody tr').filter({ hasText: record.title });
  }

  test.describe('Content Management @smoke @content', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page);
    });

    test('should display content list', async ({ page }) => {
      // Create first: with zero rows the table is replaced by an empty-state panel, so asserting the
      // table exists is only meaningful once this test owns a row.
      await createRecord(page);
      await page.goto('/admin/content');

      await expect(page.locator('h1').first()).toContainText('Content Management');
      // `.first()` — the advanced-search modal carries a second copy of both selects.
      await expect(page.locator('select[name="model"]').first()).toBeVisible();
      await expect(page.locator('select[name="status"]').first()).toBeVisible();
      await expect(page.locator('table')).toBeVisible();
      await expect(page.locator('tbody tr').first()).toBeVisible();
    });

    test('should show existing content', async ({ page }) => {
      const record = await createRecord(page);
      await page.goto(searchUrl(record.title));

      // Exactly one row, and it is this test's: the title is stamped, and `search` is applied in SQL.
      await expect(page.locator('tbody tr')).toHaveCount(1);
      await expect(rowFor(page, record)).toContainText(record.slug);
    });

    test('should filter content by status', async ({ page }) => {
      const record = await createRecord(page);
      await page.goto(searchUrl(record.title));
      await expect(rowFor(page, record)).toHaveCount(1);

      const statusSelect = page.locator('select[name="status"]').first();

      // `updateContentFilters` assigns `window.location.href` — a full navigation, not an htmx swap,
      // so there is no request to wait for and `waitForHTMX` would return immediately. It preserves
      // the existing query string, so `collection` and `search` survive the change.
      await Promise.all([
        page.waitForURL((url) => url.searchParams.get('status') === 'published'),
        statusSelect.selectOption('published'),
      ]);

      // The record was saved as a draft, so the published view must not contain it. With no rows the
      // list renders its empty-state panel instead of a table.
      await expect(page.locator('tbody tr')).toHaveCount(0);
      await expect(page.getByText('No content found')).toBeVisible();

      await Promise.all([
        page.waitForURL((url) => url.searchParams.get('status') === 'draft'),
        statusSelect.selectOption('draft'),
      ]);

      await expect(rowFor(page, record)).toHaveCount(1);
      // The document-backed branch capitalises the badge label (the all-view union emits the raw
      // lowercase status instead — that view is checked by `should filter content by collection`).
      await expect(rowFor(page, record).locator('span').filter({ hasText: /^Draft$/ })).toBeVisible();
    });

    test('should filter content by collection', async ({ page }) => {
      const record = await createRecord(page);

      // Start on the all-view so the collection filter has something to narrow.
      await page.goto(searchUrl(record.title, 'all'));
      await expect(rowFor(page, record)).toHaveCount(1);

      const modelSelect = page.locator('select[name="model"]').first();
      const e2eOption = modelSelect.locator('option[value="e2e_test"]');
      const e2eLabel = ((await e2eOption.textContent()) || '').trim();
      expect(e2eLabel).not.toBe('');

      // The Model column shows the type's display name, not its id.
      await expect(rowFor(page, record)).toContainText(e2eLabel);

      await Promise.all([
        page.waitForURL((url) => url.searchParams.get('model') === 'e2e_test'),
        modelSelect.selectOption('e2e_test'),
      ]);
      await expect(rowFor(page, record)).toHaveCount(1);

      // Narrowing to any other model must drop it.
      const otherValues = await modelSelect
        .locator('option')
        .evaluateAll((opts) => opts.map((o) => (o as HTMLOptionElement).value));
      const other = otherValues.find((v) => v !== 'all' && v !== 'e2e_test');
      expect(other, `the models dropdown offered only e2e_test: ${otherValues.join(', ')}`).toBeTruthy();

      await Promise.all([
        page.waitForURL((url) => url.searchParams.get('model') === other),
        modelSelect.selectOption(other!),
      ]);
      await expect(rowFor(page, record)).toHaveCount(0);
    });

    test('should navigate to new content form', async ({ page }) => {
      // The content list's "New Content" is a per-collection dropdown now (#885); the full-page
      // collection selector still lives at /admin/content/new.
      await page.goto('/admin/content/new');

      await expect(page.locator('h1')).toContainText('Create New Content');
      await expect(page.getByText('Select a collection')).toBeVisible();

      // The selector links by collection id, which for a doc-backed collection is its name — this is
      // the URL the rest of the suite navigates to directly.
      await expect(page.locator('a[href="/admin/content/new?collection=e2e_test"]')).toBeVisible();

      await page.locator('a[href^="/admin/content/new?collection="]').first().click();
      await expect(page.locator('form#content-form')).toBeVisible();
    });

    test('should display content actions', async ({ page }) => {
      const record = await createRecord(page);
      await page.goto(searchUrl(record.title));

      const row = rowFor(page, record);
      await expect(row.locator('button[title="Edit"]')).toBeVisible();
      await expect(row.locator('button[title="View API"]')).toBeVisible();
      await expect(row.locator('a[title="Delete"]')).toBeVisible();

      // Edit must reach this record's form, not whichever row the list happened to render first.
      await row.locator('button[title="Edit"]').click();
      await page.waitForURL((url) => url.pathname === `/admin/content/${record.id}/edit`);
      await expect(page.locator('input[name="title"]')).toHaveValue(record.title);
    });

    test('should handle bulk selection', async ({ page }) => {
      const record = await createRecord(page);
      await page.goto(searchUrl(record.title));

      const bulkButton = page.locator('#bulk-actions-btn');
      const selectAll = page.locator('input[id^="select-all-"]');
      const rowCheckbox = page.locator(`.row-checkbox[value="${record.id}"]`);

      await expect(bulkButton).toBeDisabled();
      await expect(rowCheckbox).not.toBeChecked();

      // The select-all handler is a delegated `change` listener (htmx swaps the table in), so it ticks
      // every `.row-checkbox` in the table and re-runs `updateBulkActionsButton`.
      await selectAll.check();
      await expect(rowCheckbox).toBeChecked();
      await expect(bulkButton).toBeEnabled();

      await selectAll.uncheck();
      await expect(rowCheckbox).not.toBeChecked();
      await expect(bulkButton).toBeDisabled();
    });

    test('should refresh content list', async ({ page }) => {
      const record = await createRecord(page);
      await page.goto(searchUrl(record.title));
      await expect(rowFor(page, record)).toHaveCount(1);

      // Refresh is `onclick="location.reload()"` — a navigation, so the filters in the URL and the row
      // itself both have to survive it.
      await Promise.all([
        page.waitForResponse(
          (r) => r.request().isNavigationRequest() && new URL(r.url()).pathname === '/admin/content'
        ),
        page.locator('button').filter({ hasText: 'Refresh' }).click(),
      ]);

      await expect(rowFor(page, record)).toHaveCount(1);
      await expect(page.locator('select[name="status"]').first()).toHaveValue('all');
    });

    test('should handle pagination', async ({ page }) => {
      // Two records sharing one search term, one per page.
      const stamp = `Page probe ${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      const first = await createRecord(page, `${stamp} a`);
      const second = await createRecord(page, `${stamp} b`);
      expect(first.id).not.toBe(second.id);

      await page.goto(`${searchUrl(stamp)}&limit=1`);

      const summary = page.locator('p').filter({ hasText: /Showing/ }).first();
      await expect(summary).toBeVisible();
      const shown = ((await summary.textContent()) || '').replace(/\s+/g, ' ');
      expect(shown, `pagination summary read "${shown}"`).toContain('Showing 1 to 1 of 2 results');
      await expect(page.locator('tbody tr')).toHaveCount(1);

      // Which record lands on page 1 is NOT predictable: the list is `ORDER BY updated_at DESC` and
      // `documents.updated_at` is stored in SECONDS, so two records written inside the same second
      // tie and SQLite breaks the tie however it likes. Read page 1 and require page 2 to hold the
      // other one — that is the property pagination has to guarantee either way.
      const titles = [first.title, second.title];
      const page1Row = await page.locator('tbody tr').first().innerText();
      const firstShown = titles.find((t) => page1Row.includes(t));
      expect(firstShown, `page 1 row matched neither record: ${page1Row}`).toBeTruthy();

      // The pagination nav is rendered twice — a mobile block that `sm:hidden` hides at Playwright's
      // default 1280px viewport, and the desktop one. A role locator only sees the a11y tree, so the
      // display:none copy is excluded and this stays strict-mode safe.
      const nextLink = page.getByRole('link', { name: 'Next' });
      const [nav] = await Promise.all([
        page.waitForResponse(
          (r) =>
            r.request().isNavigationRequest() && new URL(r.url()).searchParams.get('page') === '2'
        ),
        nextLink.click(),
      ]);
      expect(nav.ok(), `page 2 returned ${nav.status()}`).toBeTruthy();
      await page.waitForURL((url) => url.searchParams.get('page') === '2');

      await expect(page.locator('tbody tr')).toHaveCount(1);
      const page2Row = await page.locator('tbody tr').first().innerText();
      const secondShown = titles.find((t) => t !== firstShown)!;
      expect(page2Row, `page 2 repeated the page 1 row`).toContain(secondShown);

      const page2Summary = ((await summary.textContent()) || '').replace(/\s+/g, ' ');
      expect(page2Summary, `page 2 summary read "${page2Summary}"`).toContain(
        'Showing 2 to 2 of 2 results'
      );
    });

    test('should display content metadata', async ({ page }) => {
      const record = await createRecord(page);
      await page.goto(searchUrl(record.title));

      // The leading `<th>` holds the select-all checkbox and reads as '', so header indexes line up
      // with the row's `<td>` indexes.
      const headers = (await page.locator('thead th').allInnerTexts()).map((h) => h.trim());
      const columnIndex = (label: string): number => {
        const i = headers.indexOf(label);
        expect(i, `no "${label}" column in: ${headers.join(' | ')}`).toBeGreaterThan(-1);
        return i;
      };

      const cells = rowFor(page, record).locator('td');
      // `selectable: true` prepends a checkbox cell to both the header and every row.
      await expect(cells).toHaveCount(headers.length);

      await expect(cells.nth(columnIndex('Title'))).toContainText(record.title);
      await expect(cells.nth(columnIndex('Model'))).not.toBeEmpty();
      await expect(cells.nth(columnIndex('Status'))).toHaveText(/^\s*Draft\s*$/);
      await expect(cells.nth(columnIndex('Author'))).toContainText('@');
      // Rendered with `toLocaleDateString()` on the server, so match digits rather than a format.
      await expect(cells.nth(columnIndex('Updated'))).toHaveText(/\d{1,4}[/-]\d{1,2}[/-]\d{1,4}/);
    });

    test('should create new content and land on its edit form', async ({ page }) => {
      // Was "…and redirect to content list", which it never did: the create POST answers with an
      // HX-Redirect to the new record's edit form.
      const before = await page.goto('/admin/content');
      expect(before?.ok()).toBeTruthy();

      const record = await createRecord(page, 'Created item');
      expect(page.url()).toContain(`/admin/content/${record.id}/edit`);
      await expect(page.locator('input[name="title"]')).toHaveValue(record.title);

      await page.goto(searchUrl(record.title));
      await expect(page.locator('tbody tr')).toHaveCount(1);
      await expect(rowFor(page, record)).toContainText(record.slug);
    });
  });
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 100-content-title-preserved-on-edit.spec.ts", () => {
  test.describe('Content title preserved after edit @content', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('editing Example item (no title in schema) preserves title on list page', async ({ page }) => {
      // Example collection schema has name/emoji/description but NO title property.
      // Title is derived from data.name on save. This test verifies that editing
      // an item doesn't replace its title with the document ID.

      // Navigate to Example collection content list
      await page.goto('/admin/content?collection=example')
      await page.waitForSelector('table')

      // Find a seeded mood link by its title text (inside <a> tag in the title column)
      const moodLink = page.locator('table tbody tr a').filter({ hasText: /^(Cruel|Melancholy|Chaotic)$/ }).first()
      await expect(moodLink).toBeVisible({ timeout: 10000 })

      const originalTitle = (await moodLink.innerText()).trim()

      // Click to edit
      await moodLink.click()
      await page.waitForURL(/\/admin\/content\/.*\/edit/)

      // Verify the name field has the correct value
      const nameInput = page.locator('input[name="name"]')
      await expect(nameInput).toBeVisible()
      const nameValue = await nameInput.inputValue()
      expect(nameValue).toBe(originalTitle)

      // Save without changing anything
      await page.click('button:has-text("Save")')

      // A plain `save` over htmx does not navigate at all — the handler returns an inline
      // success banner and the URL stays on /admin/content/<id>/edit. So there was nothing for
      // `waitForURL(/\/admin\/content/)` to wait for, and it matched the current URL anyway; the
      // goto below could abort the POST this spec exists to assert on. Wait for the banner.
      // `.last()` because htmx holds the outgoing node alongside the swapped-in one for the
      // duration of the settle, so the id is briefly non-unique.
      await expect(page.locator('#form-messages').last()).toContainText(/successfully/i, {
        timeout: 15000,
      })

      // Navigate to the Example collection list page
      await page.goto('/admin/content?collection=example')
      await page.waitForSelector('table')

      // Verify the title link still shows the mood name — NOT a document ID
      const titleAfterEdit = page.locator('table tbody tr a').filter({ hasText: originalTitle })
      await expect(titleAfterEdit).toBeVisible({ timeout: 10000 })
    })

    test('creating new Example item derives title from name field', async ({ page }) => {
      const testName = `TestMood-${Date.now()}`

      // Create a new Example item via the admin form
      await page.goto('/admin/content/new?collection=example')
      await page.waitForSelector('form')

      // Fill in the name field (title should be derived from this)
      await page.fill('input[name="name"]', testName)
      await page.fill('input[name="emoji"]', '🧪')
      await page.fill('input[name="description"]', 'E2E test mood')

      // Save. The POST's `HX-Redirect` is what says it worked — waiting on the navigation alone
      // cannot tell a save still in flight from one that came back with a validation error htmx will
      // never navigate for, and reported both as a 15s timeout pointing at fixtures.ts in CI.
      await saveNewContent(page, () => page.click('button:has-text("Save")'))

      // Navigate to the Example collection list page
      await page.goto('/admin/content?collection=example')
      await page.waitForSelector('table')

      const newItem = page.locator('table tbody tr a').filter({ hasText: testName })
      await expect(newItem).toBeVisible({ timeout: 10000 })
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 125-content-delete-confirmation-page.spec.ts", () => {
  const test = source5_test;
  const expect = source6_expect;
  const NEW_RECORD_FORM = '/admin/content/new?collection=e2e_test'

  type Record = { id: string; title: string; slug: string }

  async function createRecord(page: Page, label = 'Delete test'): Promise<Record> {
    const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    const title = `${label} ${stamp}`
    const slug = `${label.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${stamp}`

    await page.goto(NEW_RECORD_FORM)
    await page.fill('input[name="title"]', title)
    await page.fill('input[name="slug"]', slug)
    await page.selectOption('select[name="status"]', 'draft')

    const editPath = await saveNewContent(page, () =>
      page.locator('button[type="submit"]').filter({ hasText: /Save|Create/ }).first().click()
    )
    return { id: editPath.split('/')[3], title, slug }
  }

  test.describe('Content Delete Confirmation Page @content', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('delete button navigates to confirmation page', async ({ page }) => {
      const record = await createRecord(page)

      // Should be on edit page after creation
      await expect(page).toHaveURL(new RegExp(`/admin/content/${record.id}/edit`))

      // Find delete link
      const deleteLink = page.locator('a:has-text("Delete Content")')
      await expect(deleteLink).toBeVisible()

      // Verify href points to delete confirmation
      const href = await deleteLink.getAttribute('href')
      expect(href).toContain(`/admin/content/${record.id}/delete`)

      // Navigate to confirmation page
      await deleteLink.click()
      await page.waitForURL(`**/admin/content/${record.id}/delete**`)

      // Verify confirmation page elements
      await expect(page.locator('h1:has-text("Delete Content")')).toBeVisible()
      await expect(page.locator('text=Review before permanently removing')).toBeVisible()
      await expect(page.locator('text=removed from the site and hidden from all lists')).toBeVisible()

      // Verify content title displayed
      await expect(page.locator(`text=${record.title}`)).toBeVisible()

      // Verify action buttons
      await expect(page.locator('a:has-text("Cancel")')).toBeVisible()
      await expect(page.locator('button:has-text("Delete Content")')).toBeVisible()
    })

    test('cancel button returns to edit page', async ({ page }) => {
      const record = await createRecord(page, 'Cancel test')

      await page.goto(`/admin/content/${record.id}/delete`)
      await expect(page.locator('h1:has-text("Delete Content")')).toBeVisible()

      // Click cancel
      await page.locator('a:has-text("Cancel")').click()
      await page.waitForURL(`**/admin/content/${record.id}/edit**`)

      // Should be back on edit page
      await expect(page.locator('h1:has-text("Edit")')).toBeVisible()
    })

    test('delete permanently removes content and redirects', async ({ page }) => {
      const record = await createRecord(page, 'Perm delete')

      await page.goto(`/admin/content/${record.id}/delete`)
      await expect(page.locator('h1:has-text("Delete Content")')).toBeVisible()

      // Confirm delete
      await page.locator('button:has-text("Delete Content")').click()

      // Should redirect to content list
      await page.waitForURL('**/admin/content**')
      expect(page.url()).not.toContain(record.id)

      // Verify content is gone - the edit page for a deleted record must not render the editor
      await page.goto(`/admin/content/${record.id}/edit`)
      const finalUrl = page.url()
      const stillOnEditPage = finalUrl.includes(`/admin/content/${record.id}/edit`)
      if (stillOnEditPage) {
        await expect(page.locator('text=Content not found')).toBeVisible()
      } else {
        expect(finalUrl).not.toContain(record.id)
      }
    })

    test('confirmation page shows content metadata', async ({ page }) => {
      const record = await createRecord(page, 'Metadata test')

      await page.goto(`/admin/content/${record.id}/delete`)

      // Check metadata labels
      await expect(page.locator('dt:has-text("Title")')).toBeVisible()
      await expect(page.locator('dt:has-text("Collection")')).toBeVisible()
      await expect(page.locator('dt:has-text("Slug")')).toBeVisible()
      await expect(page.locator('dt:has-text("Status")')).toBeVisible()
      await expect(page.locator('dt:has-text("Created")')).toBeVisible()
      await expect(page.locator('dt:has-text("Last Updated")')).toBeVisible()
      await expect(page.locator('dt:has-text("ID")')).toBeVisible()

      // Verify values
      await expect(page.locator(`dd:has-text("${record.title}")`)).toBeVisible()
      await expect(page.locator(`dd:has-text("${record.slug}")`)).toBeVisible()
    })

    test('nonexistent content redirects to list', async ({ page }) => {
      await page.goto('/admin/content/nonexistent-id-12345/delete')
      await page.waitForURL('**/admin/content**')
      expect(page.url()).not.toContain('nonexistent-id-12345')
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 23-content-api-crud.spec.ts", () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:8787';

  // Test data
  let testCollectionId: string;
  let testContentId: string;
  // Full Better Auth session cookie string captured from an authenticated context (the old
  // auth_token/JWT cookie no longer exists — auth is session-based now).
  let cookieHeader = '';

  test.describe('Content API CRUD Operations @smoke @content @api', () => {
    test.beforeAll(async ({ browser }) => {
      const context = await browser.newContext();
      const page = await context.newPage();

      await ensureAdminUserExists(page);
      await loginAsAdmin(page);

      // Capture the whole authenticated cookie jar (Better Auth session token).
      const cookies = await context.cookies();
      cookieHeader = cookies.map(c => `${c.name}=${c.value}`).join('; ');

      await context.close();
    });

    test.beforeEach(async ({ request }) => {
      // Get a collection to use for testing
      const collectionsResponse = await request.get(`${BASE_URL}/api/collections`);
      expect(collectionsResponse.ok()).toBeTruthy();

      const collectionsData = await collectionsResponse.json();
      if (collectionsData.data && collectionsData.data.length > 0) {
        testCollectionId = collectionsData.data[0].id;
        console.log(`Using collection ID: ${testCollectionId} (${collectionsData.data[0].name})`);
      }
    });

    test.describe('POST /api/content - Create Content', () => {
      test('should create new content with valid data', async ({ request }) => {
        const newContent = {
          collectionId: testCollectionId,
          title: `Test Content ${Date.now()}`,
          slug: `test-content-${Date.now()}`,
          status: 'draft',
          data: {
            content: 'This is test content created via API',
            excerpt: 'Test excerpt'
          }
        };

        const response = await request.post(`${BASE_URL}/api/content`, {
          data: newContent,
          headers: {
            'Content-Type': 'application/json',
            'Cookie': cookieHeader, 'Origin': BASE_URL
          }
        });

        console.log(`Response status: ${response.status()}`);

        if (!response.ok()) {
          const errorBody = await response.text();
          console.log(`Error response: ${errorBody}`);
        }

        expect(response.status()).toBe(201);

        const responseData = await response.json();
        console.log(`Created content with ID: ${responseData.data.id}`);

        // Verify response structure
        expect(responseData.data).toBeDefined();
        expect(responseData.data.id).toBeDefined();
        expect(responseData.data.title).toBe(newContent.title);
        expect(responseData.data.slug).toBe(newContent.slug);
        expect(responseData.data.status).toBe(newContent.status);
        expect(responseData.data.collectionId).toBe(testCollectionId);

        // Store for cleanup
        testContentId = responseData.data.id;
      });

      test('should require authentication for content creation', async ({ request }) => {
        const newContent = {
          collectionId: testCollectionId,
          title: 'Unauthorized Test',
          status: 'draft'
        };

        const response = await request.post(`${BASE_URL}/api/content`, {
          data: newContent,
          headers: {
            'Content-Type': 'application/json'
            // No auth token
          }
        });

        // Should return 401 Unauthorized or 403 Forbidden
        expect([401, 403]).toContain(response.status());
      });

      test('should validate required fields', async ({ request }) => {
        // Missing required fields
        const invalidContent = {
          collectionId: testCollectionId
          // Missing title
        };

        const response = await request.post(`${BASE_URL}/api/content`, {
          data: invalidContent,
          headers: {
            'Content-Type': 'application/json',
            'Cookie': cookieHeader, 'Origin': BASE_URL
          }
        });

        // Should return 400 Bad Request for validation error
        expect(response.status()).toBe(400);

        const errorData = await response.json();
        expect(errorData.error).toBeDefined();
        console.log(`Validation error: ${errorData.error}`);
      });

      test('should auto-generate slug if not provided', async ({ request }) => {
        const newContent = {
          collectionId: testCollectionId,
          title: `Auto Slug Test ${Date.now()}`,
          status: 'draft',
          data: {}
        };

        const response = await request.post(`${BASE_URL}/api/content`, {
          data: newContent,
          headers: {
            'Content-Type': 'application/json',
            'Cookie': cookieHeader, 'Origin': BASE_URL
          }
        });

        // A failed create used to skip every assertion below it.
        expect(response.ok(), `create failed: ${response.status()}`).toBeTruthy();
        {
          const responseData = await response.json();

          // Slug should be generated from title
          expect(responseData.data.slug).toBeDefined();
          expect(responseData.data.slug).toContain('auto-slug-test');

          console.log(`Auto-generated slug: ${responseData.data.slug}`);

          // Cleanup
          if (responseData.data.id) {
            await request.delete(`${BASE_URL}/api/content/${responseData.data.id}`, {
              headers: { 'Cookie': cookieHeader, 'Origin': BASE_URL }
            });
          }
        }
      });

      test('should prevent duplicate slugs within same collection', async ({ request }) => {
        const uniqueSlug = `unique-slug-${Date.now()}`;

        const firstContent = {
          collectionId: testCollectionId,
          title: 'First Content',
          slug: uniqueSlug,
          status: 'draft'
        };

        // Create first content
        const firstResponse = await request.post(`${BASE_URL}/api/content`, {
          data: firstContent,
          headers: {
            'Content-Type': 'application/json',
            'Cookie': cookieHeader, 'Origin': BASE_URL
          }
        });

        // Without the first row there is nothing to collide with, so a failed create here
        // meant the duplicate-slug rule was never exercised at all.
        expect(firstResponse.ok(), `could not seed the first row: ${firstResponse.status()}`).toBeTruthy();

        const firstData = await firstResponse.json();
        const firstId = firstData.data.id;

        // Try to create second content with same slug
        const secondContent = {
          collectionId: testCollectionId,
          title: 'Second Content',
          slug: uniqueSlug, // Same slug
          status: 'draft'
        };

        const secondResponse = await request.post(`${BASE_URL}/api/content`, {
          data: secondContent,
          headers: {
            'Content-Type': 'application/json',
            'Cookie': cookieHeader, 'Origin': BASE_URL
          }
        });

        // Should fail with 400 or 409 (Conflict)
        expect([400, 409]).toContain(secondResponse.status());

        const errorData = await secondResponse.json();
        console.log(`Duplicate slug error: ${errorData.error}`);

        // Cleanup
        await request.delete(`${BASE_URL}/api/content/${firstId}`, {
          headers: { 'Cookie': cookieHeader, 'Origin': BASE_URL }
        });
      });
    });

    test.describe('PUT /api/content/:id - Update Content', () => {
      let contentToUpdate: string;

      test.beforeEach(async ({ request }) => {
        // Create content to update
        const newContent = {
          collectionId: testCollectionId,
          title: `Update Test ${Date.now()}`,
          slug: `update-test-${Date.now()}`,
          status: 'draft',
          data: {
            content: 'Original content'
          }
        };

        const response = await request.post(`${BASE_URL}/api/content`, {
          data: newContent,
          headers: {
            'Content-Type': 'application/json',
            'Cookie': cookieHeader, 'Origin': BASE_URL
          }
        });

        // Swallowing a failed create here is what made the tests below pass without
        // running: each one checked `if (!contentToUpdate) return`, so a broken POST /api/content
        // turned this whole describe block into a no-op instead of a failure.
        expect(response.ok(), `could not create content for the update tests: ${response.status()}`).toBeTruthy();
        const responseData = await response.json();
        contentToUpdate = responseData.data.id;
      });

      test.afterEach(async ({ request }) => {
        // Cleanup
        if (contentToUpdate) {
          await request.delete(`${BASE_URL}/api/content/${contentToUpdate}`, {
            headers: { 'Cookie': cookieHeader, 'Origin': BASE_URL }
          });
        }
      });

      test('should update existing content', async ({ request }) => {
        const updates = {
          title: 'Updated Title',
          status: 'published',
          data: {
            content: 'Updated content',
            excerpt: 'Updated excerpt'
          }
        };

        const response = await request.put(`${BASE_URL}/api/content/${contentToUpdate}`, {
          data: updates,
          headers: {
            'Content-Type': 'application/json',
            'Cookie': cookieHeader, 'Origin': BASE_URL
          }
        });

        console.log(`Update response status: ${response.status()}`);

        if (!response.ok()) {
          const errorBody = await response.text();
          console.log(`Error response: ${errorBody}`);
        }

        expect(response.ok()).toBeTruthy();

        const responseData = await response.json();

        // Verify updates were applied
        expect(responseData.data.title).toBe(updates.title);
        expect(responseData.data.status).toBe(updates.status);

        console.log('✓ Content updated successfully');
      });

      test('should return 404 for non-existent content', async ({ request }) => {
        const fakeId = '00000000-0000-0000-0000-000000000000';

        const response = await request.put(`${BASE_URL}/api/content/${fakeId}`, {
          data: { title: 'Updated' },
          headers: {
            'Content-Type': 'application/json',
            'Cookie': cookieHeader, 'Origin': BASE_URL
          }
        });

        expect(response.status()).toBe(404);
      });

      test('should require authentication for updates', async ({ request }) => {
        const response = await request.put(`${BASE_URL}/api/content/${contentToUpdate}`, {
          data: { title: 'Unauthorized Update' },
          headers: {
            'Content-Type': 'application/json'
            // No auth token
          }
        });

        expect([401, 403]).toContain(response.status());
      });

      test('should preserve unchanged fields', async ({ request }) => {
        // Get original content (authenticated — drafts are hidden from anonymous callers).
        const getResponse = await request.get(`${BASE_URL}/api/content/${contentToUpdate}`, {
          headers: { 'Cookie': cookieHeader, 'Origin': BASE_URL }
        });
        const originalData = await getResponse.json();
        const originalTitle = originalData.data.title;

        // Update only status
        const updates = {
          status: 'published'
        };

        const updateResponse = await request.put(`${BASE_URL}/api/content/${contentToUpdate}`, {
          data: updates,
          headers: {
            'Content-Type': 'application/json',
            'Cookie': cookieHeader, 'Origin': BASE_URL
          }
        });

        // The entire body of this test was conditional on the PUT succeeding, so a broken
        // partial update passed it.
        expect(updateResponse.ok(), `partial update failed: ${updateResponse.status()}`).toBeTruthy();
        {
          const updatedData = await updateResponse.json();

          // Title should remain unchanged
          expect(updatedData.data.title).toBe(originalTitle);
          // Status should be updated
          expect(updatedData.data.status).toBe('published');

          console.log('✓ Unchanged fields preserved during partial update');
        }
      });
    });

    test.describe('DELETE /api/content/:id - Delete Content', () => {
      let contentToDelete: string;

      test.beforeEach(async ({ request }) => {
        // Create content to delete
        const newContent = {
          collectionId: testCollectionId,
          title: `Delete Test ${Date.now()}`,
          slug: `delete-test-${Date.now()}`,
          status: 'draft'
        };

        const response = await request.post(`${BASE_URL}/api/content`, {
          data: newContent,
          headers: {
            'Content-Type': 'application/json',
            'Cookie': cookieHeader, 'Origin': BASE_URL
          }
        });

        // Swallowing a failed create here is what made the tests below pass without
        // running: each one checked `if (!contentToDelete) return`, so a broken POST /api/content
        // turned this whole describe block into a no-op instead of a failure.
        expect(response.ok(), `could not create content for the delete tests: ${response.status()}`).toBeTruthy();
        const responseData = await response.json();
        contentToDelete = responseData.data.id;
      });

      test('should delete existing content', async ({ request }) => {
        const response = await request.delete(`${BASE_URL}/api/content/${contentToDelete}`, {
          headers: {
            'Cookie': cookieHeader, 'Origin': BASE_URL
          }
        });

        console.log(`Delete response status: ${response.status()}`);

        if (!response.ok()) {
          const errorBody = await response.text();
          console.log(`Error response: ${errorBody}`);
        }

        expect(response.ok()).toBeTruthy();

        const responseData = await response.json();
        expect(responseData.success).toBe(true);

        // Verify content is deleted by trying to fetch it
        const getResponse = await request.get(`${BASE_URL}/api/content/${contentToDelete}`);
        expect(getResponse.status()).toBe(404);

        console.log('✓ Content deleted successfully');

        // Clear the ID so afterEach doesn't try to delete again
        contentToDelete = '';
      });

      test('should return 404 when deleting non-existent content', async ({ request }) => {
        const fakeId = '00000000-0000-0000-0000-000000000000';

        const response = await request.delete(`${BASE_URL}/api/content/${fakeId}`, {
          headers: {
            'Cookie': cookieHeader, 'Origin': BASE_URL
          }
        });

        expect(response.status()).toBe(404);
      });

      test('should require authentication for deletion', async ({ request }) => {
        const response = await request.delete(`${BASE_URL}/api/content/${contentToDelete}`, {
          headers: {
            'Content-Type': 'application/json'
            // No auth token
          }
        });

        expect([401, 403]).toContain(response.status());
      });

      test.afterEach(async ({ request }) => {
        // Cleanup if delete test failed
        if (contentToDelete) {
          await request.delete(`${BASE_URL}/api/content/${contentToDelete}`, {
            headers: { 'Cookie': cookieHeader, 'Origin': BASE_URL }
          }).catch(() => {});
        }
      });
    });

    test.describe('Content API Integration', () => {
      test('should handle complete CRUD lifecycle', async ({ request }) => {
        // CREATE
        const newContent = {
          collectionId: testCollectionId,
          title: `Lifecycle Test ${Date.now()}`,
          slug: `lifecycle-test-${Date.now()}`,
          status: 'draft',
          data: {
            content: 'Initial content'
          }
        };

        const createResponse = await request.post(`${BASE_URL}/api/content`, {
          data: newContent,
          headers: {
            'Content-Type': 'application/json',
            'Cookie': cookieHeader, 'Origin': BASE_URL
          }
        });

        expect(createResponse.ok(), `lifecycle create failed: ${createResponse.status()}`).toBeTruthy();

        const createdData = await createResponse.json();
        const contentId = createdData.data.id;
        console.log(`✓ Created content: ${contentId}`);

        // READ (authenticated — the doc was created as a draft, hidden from anonymous callers).
        const readResponse = await request.get(`${BASE_URL}/api/content/${contentId}`, {
          headers: { 'Cookie': cookieHeader, 'Origin': BASE_URL }
        });
        expect(readResponse.ok()).toBeTruthy();
        const readData = await readResponse.json();
        expect(readData.data.title).toBe(newContent.title);
        console.log('✓ Read content successfully');

        // UPDATE
        const updateResponse = await request.put(`${BASE_URL}/api/content/${contentId}`, {
          data: {
            title: 'Updated Lifecycle Title',
            status: 'published'
          },
          headers: {
            'Content-Type': 'application/json',
            'Cookie': cookieHeader, 'Origin': BASE_URL
          }
        });

        expect(updateResponse.ok()).toBeTruthy();
        const updatedData = await updateResponse.json();
        expect(updatedData.data.title).toBe('Updated Lifecycle Title');
        expect(updatedData.data.status).toBe('published');
        console.log('✓ Updated content successfully');

        // DELETE
        const deleteResponse = await request.delete(`${BASE_URL}/api/content/${contentId}`, {
          headers: {
            'Cookie': cookieHeader, 'Origin': BASE_URL
          }
        });

        expect(deleteResponse.ok()).toBeTruthy();
        console.log('✓ Deleted content successfully');

        // Verify deletion
        const verifyResponse = await request.get(`${BASE_URL}/api/content/${contentId}`);
        expect(verifyResponse.status()).toBe(404);
        console.log('✓ Complete CRUD lifecycle successful');
      });
    });
  });
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 26-content-duplicate.spec.ts", () => {
  /**
   * Two things were wrong with every test in this file.
   *
   * 1. The real assertions sat inside `if (count > 0)`, so an empty or slow-to-render content list
   *    made the test pass having checked nothing — and the two tests that did not do that called
   *    `test.skip(count === 0)` instead, which is the same hole with a nicer label.
   *
   * 2. Each test spent its whole 120s CI budget before reaching its first assertion:
   *    `waitForLoadState('networkidle')` after every navigation (admin pages load Tailwind, Alpine,
   *    HTMX and chart.js from CDNs and may never go idle), plus `waitForTimeout(500)` for a dialog
   *    that is already open and `waitForTimeout(2000)` for a POST + page load that routinely takes
   *    longer than that on a cold preview. `should duplicate content successfully` timed out in CI
   *    on both attempts without ever clicking Duplicate.
   *
   * Each test now creates the record it duplicates, and every wait is on the thing the step
   * actually produces: the edit form, the dialog, the POST, the navigation the POST triggers.
   */

  /** Edit pages of records, not the `/admin/content/new` form. */
  const EDIT_URL = /\/admin\/content\/[^/?]+\/edit/;

  /**
   * Create a record this test owns, and return its edit URL.
   *
   * Every test here used to open `/admin/content` and duplicate whatever row happened to be first.
   * That is not a fixture, it is whatever the rest of the suite most recently wrote: locally the
   * first row was a `Cache test item ... (Copy) (Copy) (Copy)` left by the cache spec, carrying
   * empty `content` and `author`, so saving it back failed validation on required fields that were
   * already empty when the page loaded. The row also decides which fields exist at all — the edit
   * form is schema-driven, and an `example` record has `name`/`emoji`/`description` and no `title`.
   *
   * `e2e_test` exists for this: title and slug are its only required fields.
   */
  async function createRecord(page: Page): Promise<string> {
    const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    await page.goto('/admin/content/new?collection=e2e_test');
    await page.fill('input[name="title"]', `Duplicate source ${stamp}`);
    await page.fill('input[name="slug"]', `duplicate-source-${stamp}`);

    // `saveNewContent` reads the POST's `HX-Redirect` before waiting for htmx to navigate to it. A
    // bare `waitForURL(EDIT_URL)` here could not tell a save still in flight from one that came back
    // with a validation error, and reported both as a navigation timeout pointing at fixtures.ts.
    await saveNewContent(page, () =>
      page.locator('button[type="submit"]').filter({ hasText: /Save|Create/ }).first().click()
    );
    // The duplicate control lives on the edit form; waiting for it also proves the form rendered.
    await expect(page.locator('button').filter({ hasText: 'Duplicate Content' })).toBeVisible();
    return page.url();
  }

  /**
   * Click Duplicate, confirm, and wait for the copy's edit page.
   *
   * `performDuplicateContent()` POSTs the form to /admin/content/duplicate and then sets
   * `window.location` from the JSON it gets back, so there are two things to wait for and neither
   * of them is a fixed delay. The URL predicate compares against the page we started on because
   * that URL already matches EDIT_URL — waiting for the pattern alone would return immediately.
   */
  async function duplicateCurrentRecord(page: Page): Promise<void> {
    const from = page.url();
    await page.locator('button').filter({ hasText: 'Duplicate Content' }).click();

    // Scope to the dialog rather than `hasText: 'Duplicate'` + `.last()`: that filter also matches
    // the "Duplicate Content" trigger, so which button `.last()` picked depended on DOM order.
    const confirmButton = page.locator('#duplicate-content-confirm .confirm-button');
    await expect(confirmButton).toBeVisible();

    const [response] = await Promise.all([
      page.waitForResponse(
        (r) => r.request().method() === 'POST' && r.url().includes('/admin/content/duplicate')
      ),
      confirmButton.click(),
    ]);
    expect(response.ok(), `duplicate POST failed: ${response.status()}`).toBeTruthy();

    await page.waitForURL((url) => url.href !== from && EDIT_URL.test(url.pathname));
  }

  test.describe('Content Duplicate Functionality @content', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page);
    });

    test('should have duplicate button on content edit page', async ({ page }) => {
      await createRecord(page);
      await expect(page.locator('button').filter({ hasText: 'Duplicate Content' })).toBeVisible();
    });

    test('should show confirmation dialog when clicking duplicate', async ({ page }) => {
      await createRecord(page);

      await page.locator('button').filter({ hasText: 'Duplicate Content' }).click();

      const confirmDialog = page.locator('#duplicate-content-confirm');
      await expect(confirmDialog).toBeVisible();
      await expect(confirmDialog).toContainText(/Create a copy/i);
    });

    test('should duplicate content successfully', async ({ page }) => {
      await createRecord(page);

      const originalTitle = await page.locator('input[name="title"]').inputValue();

      await duplicateCurrentRecord(page);

      // Core appends a " (Copy)" suffix (admin-content.ts duplicate handler).
      const newTitle = await page.locator('input[name="title"]').inputValue();
      expect(newTitle).toContain('(Copy)');
      expect(newTitle).toContain(originalTitle);
    });

    test('should create independent copy of content', async ({ page }) => {
      const originalUrl = await createRecord(page);

      await duplicateCurrentRecord(page);
      expect(page.url()).not.toBe(originalUrl);

      // Modify the duplicate with a marker unique to this run.
      const modifiedMarker = ` - Modified ${Date.now()}`;
      const titleInput = page.locator('input[name="title"]');
      await titleInput.fill((await titleInput.inputValue()) + modifiedMarker);

      await page.locator('button[type="submit"]').filter({ hasText: /Update|Save/ }).first().click();
      // Saving is an htmx POST that swaps a banner in rather than navigating, so there is no
      // navigation to wait for — and the `goto` below would cancel the request in flight.
      // `.last()` because htmx keeps the outgoing node alongside the swapped-in one while settling.
      await expect(page.locator('#form-messages').last()).toContainText(/successfully/i, {
        timeout: 15000,
      });

      // The original must not have picked up the edit made to the copy.
      await page.goto(originalUrl);
      const originalTitleAfter = await page.locator('input[name="title"]').inputValue();
      expect(originalTitleAfter).not.toContain(modifiedMarker);
    });

    test('should carry the record data over to the duplicate', async ({ page }) => {
      // Was "should handle duplicate with all field types", which duplicated a record and then
      // checked the title suffix — the same assertion as the test above it, and nothing about any
      // field. Check a field other than the one the handler rewrites.
      await createRecord(page);

      const slugInput = page.locator('input[name="slug"]');
      await expect(slugInput).toBeVisible();
      const originalSlug = await slugInput.inputValue();
      expect(originalSlug).not.toBe('');

      await duplicateCurrentRecord(page);

      // The handler spreads the original's data into the copy and only overrides the title, then
      // gives the row a fresh `<slug>-copy-<timestamp>` so the two do not collide.
      expect(await page.locator('input[name="title"]').inputValue()).toContain('(Copy)');
      expect(await page.locator('input[name="slug"]').inputValue()).toContain(originalSlug);
    });

    test('should preserve content status as draft on duplicate', async ({ page }) => {
      await createRecord(page);
      await duplicateCurrentRecord(page);

      // `publishOnCreate: false` in the duplicate handler, so the copy is always a draft. The old
      // version of this test read the same select behind `if (count > 0)` and asserted nothing when
      // it was absent.
      const statusSelect = page.locator('select[name="status"]');
      await expect(statusSelect).toBeVisible();
      expect(await statusSelect.inputValue()).toBe('draft');
    });

    test('should handle duplicate button visibility', async ({ page }) => {
      // The list page offers no per-row duplicate control — it is an edit-form action only.
      await page.goto('/admin/content?collection=e2e_test');
      await expect(page.locator('a[href*="/admin/content/"][href*="/edit"]').first()).toBeVisible();
      expect(await page.locator('button').filter({ hasText: 'Duplicate Content' }).count()).toBe(0);

      await createRecord(page);
      await expect(page.locator('button').filter({ hasText: 'Duplicate Content' })).toBeVisible();
    });

    test('should navigate to duplicated content after duplication', async ({ page }) => {
      const originalUrl = await createRecord(page);

      await duplicateCurrentRecord(page);

      // Should be on the edit page of the NEW content (different ID).
      const newUrl = page.url();
      expect(newUrl).toContain('/admin/content/');
      expect(newUrl).toContain('/edit');
      expect(newUrl).not.toBe(originalUrl);

      expect(await page.locator('input[name="title"]').inputValue()).toContain('(Copy)');
    });
  });
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 42-content-deletion-bug.spec.ts", () => {
  /**
   * Test for GitHub Issue #522: Content Deletion UI Bug
   *
   * Bug: deleting content through Admin > Contents threw
   * "Identifier 'currentBulkAction' has already been declared" — htmx re-executes the script tags it
   * swaps in, and a `let` at the top level of the content list redeclared in the same scope. It is
   * `var` now (admin-content-list.template.ts), which tolerates redeclaration.
   *
   * Every test in this file used to be unable to fail. Each one opened the unfiltered content list,
   * took whatever row happened to be first, and guarded every step with `test.skip(true, '…')` —
   * ten of them, one per thing that might not be there. "Could not create test content" is a product
   * failure; reporting it as a skip is how a red suite stays green. The row they deleted also
   * belonged to whichever spec had most recently written one, so a run could delete another test's
   * fixture out from under it.
   *
   * Each test now creates the records it deletes, addresses them by id, and waits on the request the
   * click produces rather than on a fixed timeout.
   */

  /** Only this spec's own records — `e2e_test` needs title and slug and nothing else. */
  const LIST_URL = '/admin/content?collection=e2e_test&status=all';

  type Record = { id: string; title: string };

  async function createRecord(page: Page): Promise<Record> {
    const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const title = `Delete target ${stamp}`;

    await page.goto('/admin/content/new?collection=e2e_test');
    await page.fill('input[name="title"]', title);
    await page.fill('input[name="slug"]', `delete-target-${stamp}`);

    // `saveNewContent` reads the POST's HX-Redirect, so a validation error is reported as a failed
    // create rather than as a navigation that never happened.
    const editPath = await saveNewContent(page, () =>
      page.locator('button[type="submit"]').filter({ hasText: /Save|Create/ }).first().click()
    );

    return { id: editPath.split('/')[3], title };
  }

  /** The list row for a record, matched on the title this spec generated. */
  function rowFor(page: Page, record: Record) {
    return page.locator('tbody tr').filter({ hasText: record.title });
  }

  test.describe('Content Deletion UI Bug (Issue #522) @content', () => {
    let jsErrors: string[] = [];

    test.beforeEach(async ({ page }) => {
      jsErrors = [];

      page.on('console', (msg) => {
        if (msg.type() !== 'error') return;
        const text = msg.text();
        // CDN assets and the editor are not what this spec is watching for.
        if (!text.includes('Failed to load resource') && !text.includes('TinyMCE')) {
          jsErrors.push(text);
        }
      });

      page.on('pageerror', (error) => {
        jsErrors.push(error.message);
      });

      await loginAsAdmin(page);
    });

    /**
     * Delete one row via the confirmation-page flow and wait for the redirect to settle.
     *
     * The per-row action is a link to `/admin/content/:id/delete`, not an `hx-delete` button
     * anymore — there's no native confirm dialog to accept. Confirming on that page re-navigates
     * back to the list, which re-executes the list's script tags same as the old htmx swap did.
     */
    async function deleteRow(page: Page, record: Record) {
      const deleteLink = rowFor(page, record).locator('a[title="Delete"]');
      await expect(deleteLink).toBeVisible();
      await deleteLink.click();

      await page.waitForURL(`**/admin/content/${record.id}/delete**`);
      const confirmButton = page.locator('button:has-text("Delete Content")');
      await expect(confirmButton).toBeVisible();
      await confirmButton.click();

      await page.waitForURL('**/admin/content**');
      await waitForHTMX(page);
    }

    function assertNoRedeclarationError() {
      const offenders = jsErrors.filter(
        (error) =>
          error.includes('currentBulkAction') ||
          error.includes('has already been declared') ||
          error.includes('Identifier') ||
          error.includes('SyntaxError')
      );
      expect(offenders, `JavaScript errors during deletion: ${jsErrors.join(' | ')}`).toEqual([]);
    }

    test('should delete content without JavaScript errors', async ({ page }) => {
      const record = await createRecord(page);

      await page.goto(LIST_URL);
      await expect(rowFor(page, record)).toHaveCount(1);

      // Creating the record navigated through the editor, which loads its own scripts. Only errors
      // raised by the delete itself are this spec's business.
      jsErrors = [];

      await deleteRow(page, record);

      assertNoRedeclarationError();

      // The row is gone from the collection it was created in, not merely from whatever the
      // post-delete stub happened to render.
      await page.goto(LIST_URL);
      await expect(rowFor(page, record)).toHaveCount(0);
      await expect(page.locator('h1').first()).toContainText('Content');
    });

    test('should handle bulk delete without JavaScript errors', async ({ page }) => {
      // Two records, so the dialog takes the plural branch of updateDialogContent and the request
      // carries more than one id.
      const first = await createRecord(page);
      const second = await createRecord(page);

      await page.goto(LIST_URL);
      await expect(rowFor(page, first)).toHaveCount(1);
      await expect(rowFor(page, second)).toHaveCount(1);

      jsErrors = [];

      // Address the checkboxes by the row id they carry as `value`. The old test clicked
      // `.row-checkbox` `.first()`, which selected whichever row sorted first — someone else's.
      for (const record of [first, second]) {
        await page.locator(`.row-checkbox[value="${record.id}"]`).check();
      }

      // Selecting rows is what enables the control; that it became enabled is an assertion, not a
      // precondition to skip on.
      const bulkActionsBtn = page.locator('#bulk-actions-btn');
      await expect(bulkActionsBtn).toBeEnabled();
      await bulkActionsBtn.click();

      const deleteOption = page
        .locator('#bulk-actions-menu button')
        .filter({ hasText: 'Delete Selected' });
      await expect(deleteOption).toBeVisible();
      await deleteOption.click();

      const confirmDialog = page.locator('#bulk-action-confirm');
      await expect(confirmDialog).toBeVisible();
      await expect(confirmDialog).toContainText('delete 2 selected items');

      // `executeBulkAction` POSTs JSON and calls `location.reload()` on success, so there are two
      // things to wait for and the reload is the one that re-runs the swapped-in scripts.
      const [response] = await Promise.all([
        page.waitForResponse(
          (r) =>
            r.request().method() === 'POST' &&
            new URL(r.url()).pathname === '/admin/content/bulk-action'
        ),
        confirmDialog.locator('button.confirm-button').click(),
      ]);
      expect(response.ok(), `bulk delete failed: HTTP ${response.status()}`).toBeTruthy();

      // Both rows go away across the reload; the locator retries through the navigation.
      await expect(rowFor(page, first)).toHaveCount(0, { timeout: 15000 });
      await expect(rowFor(page, second)).toHaveCount(0);

      assertNoRedeclarationError();
      await expect(page.locator('h1').first()).toContainText('Content');
    });

    test('should maintain table functionality after delete', async ({ page }) => {
      // Two records: one to delete, one that must still be listed and filterable afterwards. The old
      // version deleted inside `if (count > 0)` and then filtered an empty table, so it could pass
      // having neither deleted nor filtered anything.
      const doomed = await createRecord(page);
      const survivor = await createRecord(page);

      await page.goto(LIST_URL);
      await deleteRow(page, doomed);

      jsErrors = [];

      await page.goto(LIST_URL);
      await expect(rowFor(page, survivor)).toHaveCount(1);

      // Filtering still works after the swap replaced the list markup. `updateContentFilters` sets
      // `window.location.href` — a full navigation that keeps the existing params and adds
      // `status=draft` — so there is no htmx request here to wait on.
      const statusSelect = page.locator('select[name="status"]').first();
      await expect(statusSelect).toBeVisible();
      await Promise.all([
        page.waitForURL((url) => url.searchParams.get('status') === 'draft'),
        statusSelect.selectOption('draft'),
      ]);
      // Records created through the form carry no `status` field, and the handler defaults to
      // 'draft', so the survivor is still listed under this filter.
      await expect(rowFor(page, survivor)).toHaveCount(1);
      await expect(rowFor(page, doomed)).toHaveCount(0);

      assertNoRedeclarationError();
      await expect(page.locator('h1').first()).toContainText('Content');
    });
  });
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 62-public-content-api-status-visibility.spec.ts", () => {
  test.describe('Public Content API Status Visibility @api @content', () => {
    let authCookie = ''
    let collectionId = ''
    let collectionName = ''
    let publishedContentId = ''
    let draftContentId = ''
    let publishedSlug = ''
    let draftSlug = ''

    test.beforeAll(async ({ browser }) => {
      const context = await browser.newContext()
      const page = await context.newPage()

      await loginAsAdmin(page)

      const cookies = await context.cookies()
      const sessionCookie = cookies.find(cookie => cookie.name.includes('session') || cookie.name.includes('auth'))
      authCookie = sessionCookie ? `${sessionCookie.name}=${sessionCookie.value}` : ''

      const collectionsResponse = await page.request.get('/api/collections')
      expect(collectionsResponse.ok()).toBeTruthy()

      const collectionsData = await collectionsResponse.json()
      const pagesCollection = collectionsData.data.find((collection: any) => collection.name === 'pages') || collectionsData.data[0]

      expect(pagesCollection).toBeDefined()

      collectionId = pagesCollection.id
      collectionName = pagesCollection.name

      const uniqueSuffix = `${Date.now()}`
      publishedSlug = `public-api-published-${uniqueSuffix}`
      draftSlug = `public-api-draft-${uniqueSuffix}`

      const publishedResponse = await page.request.post('/api/content', {
        data: {
          collectionId,
          title: `Public API Published ${uniqueSuffix}`,
          slug: publishedSlug,
          status: 'published',
          data: {
            content: 'Published content for public API visibility tests'
          }
        }
      })

      expect(publishedResponse.status()).toBe(201)
      const publishedData = await publishedResponse.json()
      publishedContentId = publishedData.data.id

      const draftResponse = await page.request.post('/api/content', {
        data: {
          collectionId,
          title: `Public API Draft ${uniqueSuffix}`,
          slug: draftSlug,
          status: 'draft',
          data: {
            content: 'Draft content for public API visibility tests'
          }
        }
      })

      expect(draftResponse.status()).toBe(201)
      const draftData = await draftResponse.json()
      draftContentId = draftData.data.id

      await context.close()
    })

    test.afterAll(async ({ browser }) => {
      if (!authCookie) {
        return
      }

      const context = await browser.newContext()
      const page = await context.newPage()

      for (const contentId of [publishedContentId, draftContentId]) {
        if (!contentId) {
          continue
        }

        await page.request.delete(`/api/content/${contentId}`, {
          headers: {
            Cookie: authCookie
          }
        })
      }

      await context.close()
    })

    test('should force published-only results for anonymous /api/content requests', async ({ request }) => {
      const where = encodeURIComponent(JSON.stringify({
        or: [
          { field: 'status', operator: 'not_equals', value: 'published' },
          { field: 'slug', operator: 'equals', value: publishedSlug },
          { field: 'slug', operator: 'equals', value: draftSlug }
        ]
      }))

      const response = await request.get(`/api/content?collection=${collectionName}&where=${where}&limit=100`)

      expect(response.ok()).toBeTruthy()

      const data = await response.json()
      const slugs = data.data.map((item: any) => item.slug)

      expect(slugs).toContain(publishedSlug)
      expect(slugs).not.toContain(draftSlug)
      expect(data.data.every((item: any) => item.status === 'published')).toBeTruthy()
      expect(data.meta.filter.where.and).toContainEqual({
        field: 'status',
        operator: 'equals',
        value: 'published'
      })
    })

    test('should force published-only results for anonymous collection-specific requests', async ({ request }) => {
      const response = await request.get(`/api/collections/${collectionName}/content?status=draft&limit=100`)

      expect(response.ok()).toBeTruthy()

      const data = await response.json()
      const slugs = data.data.map((item: any) => item.slug)

      expect(slugs).toContain(publishedSlug)
      expect(slugs).not.toContain(draftSlug)
      expect(data.data.every((item: any) => item.status === 'published')).toBeTruthy()
      expect(data.meta.filter.where.and).toContainEqual({
        field: 'status',
        operator: 'equals',
        value: 'published'
      })
    })

    test('should allow authenticated callers to request draft content explicitly', async ({ request }) => {
      const response = await request.get(`/api/content?collection=${collectionName}&status=draft&limit=100`, {
        headers: {
          Cookie: authCookie
        }
      })

      expect(response.ok()).toBeTruthy()

      const data = await response.json()
      const slugs = data.data.map((item: any) => item.slug)

      expect(slugs).toContain(draftSlug)
      expect(data.data.every((item: any) => item.status === 'draft')).toBeTruthy()
    })
  })
})

// Original module scope: hooks, fixtures and configuration stay isolated.
test.describe("Source: 63-document-blog-crud.spec.ts", () => {
  /**
   * Document-model blog posts (Option B) — E2E regression guard.
   *
   * Verifies the blog_post collection is document-backed end to end:
   *  - the admin "Blog Posts" content list renders (doc-backed list branch is wired + mounted),
   *  - the authenticated admin document API creates a blog_post document,
   *  - the public document API returns it once published, and hides drafts.
   *
   * The reliable assertions use the JSON API contracts (stable); the admin list check guards the
   * route wiring. Run locally: `npm run e2e` (needs the dev server + seeded admin + migrations 043/044).
   */



  test.describe('Blog posts on the document model (Option B) @smoke @content', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('admin Blog Posts list renders (doc-backed list branch)', async ({ page }) => {
      await page.goto('/admin/content?model=blog_post')
      await waitForHTMX(page)
      await expect(page).toHaveURL(/model=blog_post/)
      // Should not 404 / error — the content list shell is present.
      await expect(page.locator('body')).toContainText(/Blog Posts|Content|New/i)
    })

    test('create via admin document API → readable on public API once published; draft hidden', async ({ page }) => {
      const unique = await page.evaluate(() => Math.random().toString(36).slice(2, 8))
      const title = `E2E Doc Blog ${unique}`
      const slug = `e2e-doc-blog-${unique}`

      // Create a published blog_post document through the authenticated admin API (same store the UI uses).
      const createRes = await page.request.post('/admin/documents', {
        headers: { 'Content-Type': 'application/json' },
        data: {
          typeId: 'blog_post',
          title,
          slug,
          data: { author: 'E2E', difficulty: 'advanced', content: '<p>hello</p>', excerpt: 'x' },
          publishOnCreate: true,
        },
      })
      expect(createRes.ok()).toBeTruthy()

      // Public document API returns the published post.
      const pubRes = await page.request.get('/api/documents?type=blog_post&limit=100')
      expect(pubRes.ok()).toBeTruthy()
      const pub = await pubRes.json()
      const found = (pub.data ?? []).find((d: any) => d.slug === slug)
      expect(found, 'published blog doc should appear on the public API').toBeTruthy()

      // A draft (publishOnCreate omitted) must NOT appear on the public API.
      const draftSlug = `${slug}-draft`
      const draftRes = await page.request.post('/admin/documents', {
        headers: { 'Content-Type': 'application/json' },
        data: { typeId: 'blog_post', title: `${title} Draft`, slug: draftSlug, data: { author: 'E2E', difficulty: 'beginner', content: '<p>draft</p>' } },
      })
      expect(draftRes.ok()).toBeTruthy()
      const pub2 = await (await page.request.get('/api/documents?type=blog_post&limit=100')).json()
      const draftFound = (pub2.data ?? []).find((d: any) => d.slug === draftSlug)
      expect(draftFound, 'unpublished draft must be hidden from the public API').toBeFalsy()
    })

    test('Option B: creating a blog post through the content collection route stores a document', async ({ page }) => {
      // The blog editor posts to /admin/content with the collection_id; for the doc-backed blog_post
      // collection that create handler routes to the document model. Drive it via an authenticated form
      // POST to the REAL route (no fragile field selectors / Quill interaction).
      await page.goto('/admin/content/new?collection=blog_post')
      await waitForHTMX(page)
      const collectionId = await page.locator('input[name="collection_id"]').first().inputValue()
      expect(collectionId, 'blog editor should carry a collection_id').toBeTruthy()

      const unique = await page.evaluate(() => Math.random().toString(36).slice(2, 8))
      const slug = `e2e-formblog-${unique}`
      const res = await page.request.post('/admin/content', {
        multipart: {
          collection_id: collectionId,
          title: `E2E Form Blog ${unique}`,
          slug,
          author: 'E2E',
          difficulty: 'advanced',
          content: '<p>body</p>',
          excerpt: 'x',
          status: 'published',
          action: 'save_and_publish',
        },
      })
      expect([200, 302]).toContain(res.status())

      // It must now be a published blog_post DOCUMENT on the public API.
      const pub = await (await page.request.get('/api/documents?type=blog_post&limit=200')).json()
      expect((pub.data ?? []).some((d: any) => d.slug === slug), 'form-created blog post should be a published document').toBeTruthy()
    })
  })
})

test.describe("Source: 126-content-all-view-capped-count.spec.ts", () => {
  const test = source5_test;
  const expect = source6_expect;
  const NEW_RECORD_FORM = '/admin/content/new?collection=e2e_test'

  /**
   * The All view no longer runs an exact COUNT(*): it counts at most `offset + limit * 10` matches
   * (a full count over every document tripped D1's per-10s resource limit on large installs). Below
   * the window the total is exact; above it the header badge and pagination footer show "N+".
   * Each test scopes the list to its own records with `?search=<stamp>` so totals are exact.
   */
  async function createRecords(page: Page, stamp: string, n: number) {
    for (let i = 0; i < n; i++) {
      await page.goto(NEW_RECORD_FORM)
      await page.fill('input[name="title"]', `Capped ${stamp} ${i}`)
      await page.fill('input[name="slug"]', `capped-${stamp}-${i}`)
      await page.selectOption('select[name="status"]', 'draft')
      await saveNewContent(page, () =>
        page.locator('button[type="submit"]').filter({ hasText: /Save|Create/ }).first().click()
      )
    }
  }

  const footer = (page: Page) => page.locator('p', { hasText: /results/ }).first()
  const badge = (page: Page) => page.locator('span', { hasText: /^\s*\d+\+? items?\s*$/ }).first()

  test.describe('Content All view capped count @content', () => {
    test.beforeEach(async ({ page }) => {
      await loginAsAdmin(page)
    })

    test('shows an exact total when matches fit the count window, and clamps bad paging input', async ({ page }) => {
      const stamp = `${Date.now()}${Math.random().toString(36).slice(2, 6)}`
      await createRecords(page, stamp, 2)

      await page.goto(`/admin/content?model=all&search=${stamp}&limit=1`)
      await expect(footer(page)).toContainText(/of\s*2\s*results/)
      await expect(badge(page)).toHaveText(/^\s*2 items\s*$/)

      // limit=-1 used to yield a negative count cap → unbounded COUNT and a negative total.
      const res = await page.goto(`/admin/content?model=all&search=${stamp}&limit=-1&page=-3`)
      expect(res?.status()).toBe(200)
      await expect(footer(page)).toContainText(/Showing\s*1\s*to\s*1\s*of\s*2\s*results/)
    })

    test('shows a lower bound "N+" past the window and grows it when paging forward', async ({ page }) => {
      test.setTimeout(120_000) // creates 11 records through the form
      const stamp = `${Date.now()}${Math.random().toString(36).slice(2, 6)}`
      await createRecords(page, stamp, 11)

      // limit=1, page 1 → window = 10 < 11 matches → lower bound.
      await page.goto(`/admin/content?model=all&search=${stamp}&limit=1`)
      await expect(footer(page)).toContainText(/of\s*10\+\s*results/)
      await expect(badge(page)).toHaveText(/^\s*10\+ items\s*$/)

      // page 2 → offset 1, window = 11 → all 11 matches counted exactly.
      await page.goto(`/admin/content?model=all&search=${stamp}&limit=1&page=2`)
      await expect(footer(page)).toContainText(/of\s*11\s*results/)
      await expect(badge(page)).toHaveText(/^\s*11 items\s*$/)
    })
  })
})
