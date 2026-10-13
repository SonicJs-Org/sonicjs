import { test, expect, type Page } from '@playwright/test'

/**
 * An account created through the register PAGE can sign in.
 *
 * The page posts to `/auth/register/form` (htmx), not to the JSON `/auth/register`. That handler
 * used to create `auth_user` without the `auth_account` credential row Better Auth reads the
 * password from, so registration succeeded and every sign-in failed with "Invalid email or
 * password" (#1054). This drives the real page, then signs in.
 */

/**
 * Register through the page, waiting out registration being switched off.
 *
 * Spec 37 turns registration off for a few seconds at a time on the same preview database
 * (`fullyParallel`, 4 CI workers), and always switches it back on in a `finally`. Toggling the
 * setting from here would break 37's own assertions, so this waits for it to come back instead.
 */
async function registerThroughPage(page: Page, email: string, password: string) {
  for (let attempt = 0; attempt < 10; attempt++) {
    await page.goto('/auth/register')
    // Registration off: the page redirects to /auth/login.
    if (!new URL(page.url()).pathname.startsWith('/auth/register')) {
      await page.waitForTimeout(2000)
      continue
    }

    await page.fill('input[name="firstName"]', 'Form')
    await page.fill('input[name="lastName"]', 'Register')
    await page.fill('input[name="email"]', email)
    await page.fill('input[name="password"]', password)

    const response = page.waitForResponse(
      (r) => r.url().includes('/auth/register/form') && r.request().method() === 'POST',
    )
    await page.click('button[type="submit"]')
    const res = await response
    const body = await res.text()

    // Switched off between loading the page and submitting it.
    if (body.includes('Registration is currently disabled')) {
      await page.waitForTimeout(2000)
      continue
    }

    expect(res.status()).toBe(200)
    expect(body).toContain('Account created successfully')
    return
  }
  throw new Error('Registration stayed disabled for 20s; spec 37 normally re-enables it within seconds')
}

test.describe('Register page → sign in @auth', () => {
  test('a user registered through the form can log in', async ({ page, request }) => {
    const email = `form.register.${Date.now()}@example.com`
    const password = 'FormRegister12345!'

    await registerThroughPage(page, email, password)

    const login = await request.post('/auth/login', { data: { email, password } })
    expect(login.status(), await login.text()).toBe(200)
    const body = await login.json()
    expect(body.user?.email).toBe(email)

    const wrong = await request.post('/auth/login', { data: { email, password: 'not-the-password' } })
    expect(wrong.status()).toBe(401)
  })
})
