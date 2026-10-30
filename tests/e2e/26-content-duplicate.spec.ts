import { test, expect } from './fixtures';
import type { Page } from '@playwright/test';
import { loginAsAdmin, saveNewContent } from './utils/test-helpers';

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
