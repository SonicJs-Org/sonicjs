import { test, expect } from './fixtures'
import { loginAsAdmin } from './utils/test-helpers'

/**
 * Every card on /admin/plugins must carry a real plugin id and a human label.
 *
 * Two defects this guards:
 *
 *  - `definePlugin()` assigns `name = input.id` because `name` is the internal
 *    key (hook namespacing, capability errors). It used to drop the author's
 *    `name` entirely, so an *uninstalled* SDK plugin rendered its slug —
 *    "example", "graphql", "email-reconciliation". Installed ones looked fine,
 *    which is why this only ever broke on a database where the plugin happened
 *    to be uninstalled.
 *  - Pre-SDK plugin objects carry `name` but no `id`. They reached the
 *    available-plugins list and rendered a second, phantom card for a plugin
 *    the manifest registry already listed, linking to
 *    /admin/plugins/undefined/configure.
 *
 * Asserted over the whole list rather than for named plugins, so a plugin added
 * later without a display name is caught too.
 */
test.describe('Plugin card identity @plugins', () => {
  test('every plugin card has a real id and a label that is not its slug', async ({ page }) => {
    await loginAsAdmin(page)
    await page.goto('/admin/plugins')
    await page.waitForLoadState('networkidle')

    const cards = page.locator('.plugin-card')
    expect(await cards.count()).toBeGreaterThan(0)

    const offenders = await cards.evaluateAll(nodes =>
      nodes
        .map(n => ({
          id: (n.getAttribute('onclick') ?? '').match(/openPluginSettings\('([^']*)'\)/)?.[1] ?? '',
          name: n.getAttribute('data-name') ?? '',
        }))
        .filter(c => !c.id || c.id === 'undefined' || c.id === c.name)
    )

    expect(offenders, `cards missing an id or showing their slug: ${JSON.stringify(offenders)}`).toEqual([])
  })

  test('SDK plugins show the name their definition declares', async ({ page }) => {
    await loginAsAdmin(page)
    await page.goto('/admin/plugins')
    await page.waitForLoadState('networkidle')

    // examplePlugin declares `name: 'Example'`, graphqlPlugin `name: 'GraphQL API'`.
    // Both go through definePlugin and neither ships a manifest.json, so the label
    // can only come from the definition.
    await expect(page.locator('.plugin-card[data-name="Example"]')).toHaveCount(1)
    await expect(page.locator('.plugin-card[data-name="GraphQL API"]')).toHaveCount(1)
  })

  test('a plugin is listed once, not once per registration source', async ({ page }) => {
    await loginAsAdmin(page)
    await page.goto('/admin/plugins')
    await page.waitForLoadState('networkidle')

    const ids = await page
      .locator('.plugin-card')
      .evaluateAll(nodes =>
        nodes.map(n => (n.getAttribute('onclick') ?? '').match(/openPluginSettings\('([^']*)'\)/)?.[1] ?? '')
      )

    const duplicates = ids.filter((id, i) => ids.indexOf(id) !== i)
    expect(duplicates, `plugin ids rendered more than once: ${duplicates.join(', ')}`).toEqual([])
  })
})
