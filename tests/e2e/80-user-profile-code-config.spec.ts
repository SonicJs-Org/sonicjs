import { test, expect } from '@playwright/test'
import { loginAsAdmin, ensureAdminUserExists } from './utils/test-helpers'

const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'

// User profile fields are a CODE-DEFINED data model (defineUserProfile() in the
// app entry point), not editable through the admin UI. Until the developer calls
// defineUserProfile(), the "Profile Information" section stays hidden on the user
// create/edit pages, and the plugin detail page explains where to define fields.
//
// The default app entry (my-sonicjs-app/src/index.ts) does NOT call
// defineUserProfile(), so these tests assert the "unconfigured" state.
test.describe('User Profiles — code-defined config', () => {
  test.beforeEach(async ({ page }) => {
    await ensureAdminUserExists(page)
    await loginAsAdmin(page)
  })

  test('plugin detail page explains where to define fields in code', async ({ page }) => {
    const resp = await page.goto(`${BASE_URL}/admin/plugins/user-profiles`)
    await page.waitForLoadState('networkidle')

    expect(resp?.status()).not.toBe(404)
    expect(resp?.status()).not.toBe(500)

    const body = (await page.locator('body').textContent()) || ''

    // Points the developer at the code-defined data model.
    expect(body).toContain('defineUserProfile')
    expect(body).toContain('my-sonicjs-app/src/index.ts')

    // Explains the section is hidden until fields are defined.
    expect(body.toLowerCase()).toContain('profile information')
    expect(body).toContain('No profile fields defined yet')
  })

  test('user edit page hides Profile Information when no fields are defined', async ({ page }) => {
    // Grab the current admin user id from the users list.
    await page.goto(`${BASE_URL}/admin/users`)
    await page.waitForLoadState('networkidle')

    const editLink = page.locator('a[href*="/admin/users/"][href$="/edit"]').first()
    await expect(editLink).toBeVisible({ timeout: 10000 })
    const href = await editLink.getAttribute('href')
    expect(href).toBeTruthy()

    await page.goto(`${BASE_URL}${href}`)
    await page.waitForLoadState('networkidle')

    // Basic Information always present; Profile Information only when configured.
    const body = (await page.locator('body').textContent()) || ''
    expect(body).toContain('Basic Information')
    expect(body).not.toContain('Profile Information')
    // The old hard-coded "edit the template" hint must be gone.
    expect(body).not.toContain('admin-user-edit.template.ts')

    // No display-name / custom profile inputs rendered.
    await expect(page.locator('input[name="profile_display_name"]')).toHaveCount(0)
  })

  test('new user page hides Profile Information when no fields are defined', async ({ page }) => {
    await page.goto(`${BASE_URL}/admin/users/new`)
    await page.waitForLoadState('networkidle')

    const body = (await page.locator('body').textContent()) || ''
    expect(body).toContain('Basic Information')
    expect(body).not.toContain('Profile Information')

    // No registration profile inputs (custom_* fields) rendered.
    await expect(page.locator('input[name^="custom_"]')).toHaveCount(0)
  })
})
