import { test, expect } from '@playwright/test'
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers'

// User profile fields are a CODE-DEFINED data model — `defineUserProfile()` in the app
// entry point, not editable through the admin UI. The shipped app configures four fields
// in `my-sonicjs-app/src/user-profile.model.ts` (bio, company, jobTitle, website), so these
// tests assert the CONFIGURED state: the plugin page documents where the model lives and
// lists what is currently declared, and the user forms render the declared fields.
const DECLARED_FIELDS = ['bio', 'company', 'jobTitle', 'website']

test.describe('User Profiles — code-defined config @auth', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
  })

  test('plugin detail page explains where to define fields in code', async ({ page }) => {
    const resp = await page.goto('/admin/plugins/user-profiles')
    await page.waitForLoadState('networkidle')

    expect(resp?.status()).not.toBe(404)
    expect(resp?.status()).not.toBe(500)

    // The panel is the plugin's Settings tab. It has no editable keys, so it only shows
    // when the page opts it in explicitly — a regression here hides the tab entirely.
    await expect(page.locator('#settings-tab')).toBeVisible()

    const body = (await page.locator('body').textContent()) || ''

    // Points the developer at the code-defined data model.
    expect(body).toContain('defineUserProfile')
    expect(body).toContain('my-sonicjs-app/src/index.ts')
    expect(body.toLowerCase()).toContain('profile information')

    // Reports the live configuration rather than a generic "not configured" notice.
    expect(body).toContain('Profile fields configured')
    expect(body).not.toContain('No profile fields defined yet')
    expect(body).toContain('Configured Fields')
    for (const name of DECLARED_FIELDS) {
      expect(body).toContain(name)
    }
  })

  test('user edit page renders the declared profile fields', async ({ page }) => {
    // Grab a user id from the users list. Rows are not anchors — they navigate from an
    // onclick handler — so the edit path has to come out of that attribute.
    await page.goto('/admin/users')
    await page.waitForLoadState('networkidle')

    const row = page.locator('tr[onclick*="/admin/users/"]').first()
    await expect(row).toBeVisible({ timeout: 10000 })
    const onclick = await row.getAttribute('onclick')
    const href = onclick?.match(/'(\/admin\/users\/[^']+\/edit)'/)?.[1]
    expect(href).toBeTruthy()

    await page.goto(href!)
    await page.waitForLoadState('networkidle')

    const body = (await page.locator('body').textContent()) || ''
    expect(body).toContain('Basic Information')
    expect(body).toContain('Profile Information')
    // The old hard-coded "edit the template" hint must be gone — fields come from code now.
    expect(body).not.toContain('admin-user-edit.template.ts')

    await expect(page.locator('input[name="profile_display_name"]')).toHaveCount(1)
    for (const name of DECLARED_FIELDS) {
      await expect(page.locator(`[name="custom_${name}"]`)).toHaveCount(1)
    }
  })

  test('new user page renders the declared profile fields', async ({ page }) => {
    await page.goto('/admin/users/new')
    await page.waitForLoadState('networkidle')

    const body = (await page.locator('body').textContent()) || ''
    expect(body).toContain('Basic Information')
    expect(body).toContain('Profile Information')

    // registrationFields is unset in the shipped model, which means "all declared fields"
    // (see the regFieldNames fallback in routes/admin-users.ts).
    for (const name of DECLARED_FIELDS) {
      await expect(page.locator(`[name="custom_${name}"]`)).toHaveCount(1)
    }
  })
})
