import { test, expect } from '@playwright/test'
import { loginAsAdmin, getCsrfTokenFromPage, TEST_ORIGIN } from './utils/test-helpers'

/**
 * A password set by an admin is the password that signs in.
 *
 * Better Auth signs in against `auth_account.password`. Admin create-user and admin edit-user
 * used to write only `auth_user.password_hash`, so an admin-created user could not sign in at
 * all, and after an admin set a new password the old one kept working and the new one failed.
 */
test.describe('Admin-set passwords sign in @auth', () => {
  test('create a user, then change their password: new one works, old one does not', async ({ page, request }) => {
    await loginAsAdmin(page)
    const headers = { 'X-CSRF-Token': await getCsrfTokenFromPage(page), Origin: TEST_ORIGIN }

    const email = `pw.change.${Date.now()}@example.com`
    const firstPassword = 'FirstPassword12345!'
    const secondPassword = 'SecondPassword67890!'

    const created = await page.request.post('/admin/users/new', {
      headers,
      form: {
        first_name: 'Password',
        last_name: 'Change',
        email,
        role: 'role-authenticated',
        is_active: '1',
        password: firstPassword,
        confirm_password: firstPassword,
      },
    })
    expect(created.status(), await created.text()).toBe(200)

    // The admin-created user can sign in with the password the admin set.
    const first = await request.post('/auth/login', { data: { email, password: firstPassword } })
    expect(first.status(), await first.text()).toBe(200)
    const userId = (await first.json()).user?.id
    expect(userId).toBeTruthy()

    const updated = await page.request.put(`/admin/users/${userId}`, {
      headers,
      form: {
        first_name: 'Password',
        last_name: 'Change',
        email,
        role: 'role-authenticated',
        is_active: '1',
        new_password: secondPassword,
        confirm_password: secondPassword,
      },
    })
    expect(await updated.text()).toContain('User updated successfully')

    const withNew = await request.post('/auth/login', { data: { email, password: secondPassword } })
    expect(withNew.status(), await withNew.text()).toBe(200)

    const withOld = await request.post('/auth/login', { data: { email, password: firstPassword } })
    expect(withOld.status()).toBe(401)
  })
})
