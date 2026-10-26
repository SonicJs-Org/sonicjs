import { test, expect } from './fixtures';
import type { Page } from '@playwright/test';
import { loginAsAdmin, saveNewContent } from './utils/test-helpers';

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
