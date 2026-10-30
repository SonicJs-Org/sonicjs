import { test, expect } from './fixtures';
import type { Page } from '@playwright/test';
import { loginAsAdmin, saveNewContent, waitForHTMX } from './utils/test-helpers';

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
