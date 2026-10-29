import { test, expect } from './fixtures'
import { loginAsAdmin, getCsrfTokenFromPage, submitAndWaitForXhr, TEST_ORIGIN } from './utils/test-helpers'

// Roles chosen in the admin Users screen are real RBAC roles, and saving a user never promotes them.
test.describe('Admin user roles @auth @lock-auth-registration', () => {
  const signIn = async (playwright: any, email: string, password: string) => {
    const ctx = await playwright.request.newContext({ baseURL: TEST_ORIGIN, extraHTTPHeaders: { Origin: TEST_ORIGIN } })
    expect((await ctx.post('/auth/sign-in/email', { data: { email, password } })).ok()).toBeTruthy()
    return ctx
  }

  test('an editor created in the Users screen can use the admin', async ({ page, playwright }) => {
    await loginAsAdmin(page)
    const csrf = await getCsrfTokenFromPage(page)
    const email = `roles-editor-${Date.now()}@example.com`
    const password = `RolesEditor${Date.now()}!`
    const created = await page.request.post('/admin/users/new', {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...(csrf ? { 'X-CSRF-Token': csrf } : {}) },
      form: { email, first_name: 'Role', last_name: 'Editor', password, confirm_password: password, role: 'role-editor', is_active: '1', email_verified: '1' },
    })
    expect(await created.text()).not.toContain('bg-error/10')

    const editor = await signIn(playwright, email, password)
    expect((await (await editor.get('/auth/get-session')).json()).user.role).toBe('editor')
    expect((await editor.get('/admin/content', { maxRedirects: 0 })).status()).toBe(200)
    await editor.dispose()
  })

  test('saving a user who is not an admin does not make them one', async ({ page, playwright }) => {
    const email = `roles-member-${Date.now()}@example.com`
    const password = `RolesMember${Date.now()}!`
    const anon = await playwright.request.newContext({ baseURL: TEST_ORIGIN, extraHTTPHeaders: { Origin: TEST_ORIGIN } })
    const signUp = await anon.post('/auth/sign-up/email', { data: { email, password, name: 'Role Member' } })
    expect(signUp.ok()).toBeTruthy()
    const userId = (await signUp.json()).user.id
    await anon.dispose()

    await loginAsAdmin(page)
    await page.goto(`/admin/users/${userId}/edit`)
    // The old form preselected nothing, so the browser submitted the first option: Administrator.
    await expect(page.locator('select[name="role"]')).not.toHaveValue('role-admin')
    await page.fill('input[name="phone"]', '555-0100')
    await submitAndWaitForXhr(page, 'PUT', `/admin/users/${userId}`, () =>
      page.locator('button[type="submit"]').filter({ hasText: /save|update/i }).click()
    )

    const member = await signIn(playwright, email, password)
    expect(['admin', 'role-admin']).not.toContain((await (await member.get('/auth/get-session')).json()).user.role)
    await member.dispose()
  })
})
