import { test, expect } from './fixtures'

// The bootstrap middleware's path-based short-circuits (/health, static assets, Better Auth's
// stateless session API) must run BEFORE its KV fast-path. The fast path still costs a KV read,
// a `SELECT COUNT(*) FROM document_types`, a collection-config load and three serial D1 bootstrap
// calls — ~9s on a cold Cloudflare isolate, measured on a preview deployment. With the skips
// underneath it they were dead on any worker that had served a request, so health checks, assets
// and every sign-in paid that tax and CI stacked it into 90s Playwright timeouts.
//
// Asserted as a *relative* budget, not an absolute millisecond figure: a shared CI runner's
// absolute timings are noise, but a skipped path doing no I/O at all should never cost multiples
// of a path that queries D1 and renders HTML.

const BASE_URL = process.env.BASE_URL || 'http://localhost:8787'

/** Best of n attempts, so one unlucky cold isolate can't fail the run on its own. */
async function fastest(attempts: number, fn: () => Promise<void>): Promise<number> {
  let best = Infinity
  for (let i = 0; i < attempts; i++) {
    const t = Date.now()
    await fn()
    best = Math.min(best, Date.now() - t)
  }
  return best
}

test.describe('Bootstrap path skips @smoke @auth', () => {
  test('health and static assets short-circuit ahead of the bootstrap work', async ({ request }) => {
    const health = await request.get(`${BASE_URL}/health`)
    expect(health.ok()).toBeTruthy()

    // A bootstrapping path for comparison: /auth/login renders HTML and is deliberately NOT
    // skipped (it is not a hot cold-start path), so it carries the full middleware.
    const bootstrapped = await fastest(3, async () => {
      const r = await request.get(`${BASE_URL}/auth/login`)
      expect(r.ok()).toBeTruthy()
    })
    const skipped = await fastest(3, async () => {
      const r = await request.get(`${BASE_URL}/health`)
      expect(r.ok()).toBeTruthy()
    })

    // Generous: the point is to catch the skip being bypassed entirely (an order regression puts
    // a KV read + 4 D1 round-trips on this path), not to police a few ms of jitter.
    expect(skipped).toBeLessThanOrEqual(Math.max(bootstrapped * 2 + 500, 1500))
  })

  test('Better Auth sign-in answers without carrying the bootstrap', async ({ request }) => {
    // Wrong credentials on purpose: this asserts the endpoint *responds* rather than hanging on a
    // cold isolate's bootstrap — the failure mode in CI was a 90s timeout or a bare 500, both of
    // which this catches regardless of whether the password is right.
    const started = Date.now()
    const res = await request.post(`${BASE_URL}/auth/sign-in/email`, {
      data: { email: `nobody-${Date.now()}@example.com`, password: 'not-the-password' },
      headers: { 'Content-Type': 'application/json', Origin: BASE_URL },
    })
    const elapsed = Date.now() - started

    // A 4xx is the expected answer. A 500 is the cold-start bootstrap exhausting the Worker's
    // CPU budget on the same request as Better Auth's scrypt verify — the exact bug being guarded.
    expect(res.status()).toBeGreaterThanOrEqual(400)
    expect(res.status()).toBeLessThan(500)
    expect(elapsed).toBeLessThan(30_000)
  })
})
