import { test, expect } from '@playwright/test'
import { TEST_ORIGIN } from './utils/test-helpers'

/**
 * The register form must create both auth_user AND auth_account credential row
 * so that Better Auth's sign-in/email endpoint can authenticate the new user.
 */
test.describe('Register creates sign-in credential @smoke @auth', () => {
  test('registered user can sign in immediately', async ({ request }) => {
    const unique = Date.now()
    const email = `regtest-${unique}@example.com`
    const password = `RegTest${unique}!`

    // Register via the form endpoint
    const regRes = await request.post('/auth/register/form', {
      form: {
        email,
        password,
        firstName: 'Reg',
        lastName: 'Test',
      },
    })
    // Register returns 200 or redirects
    expect([200, 302].includes(regRes.status())).toBeTruthy()

    // Now sign in via Better Auth — this requires the auth_account credential row
    const signIn = await request.post('/auth/sign-in/email', {
      data: { email, password },
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
    })
    expect(signIn.ok()).toBe(true)

    // Clean up
    await request.post('/auth/sign-out', {
      data: {},
      headers: { 'Content-Type': 'application/json', Origin: TEST_ORIGIN },
    })
  })
})
