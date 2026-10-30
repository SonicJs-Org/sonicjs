/**
 * `POST /admin/two-factor/qr` — the QR renderer the enrolment page calls after Better Auth
 * returns an `otpauth://` URI.
 *
 * This exists because the page originally shipped no QR at all, which made desktop enrolment
 * effectively impossible: the admin panel is on a laptop, the authenticator is on a phone, and an
 * `otpauth://` link has nothing to open. The tests below pin the two things that matter — that it
 * really produces a scannable SVG encoding the URI, and that it cannot be used to render
 * arbitrary content as a QR from this origin.
 */
import { describe, it, expect, vi } from 'vitest'
import { Hono } from 'hono'

// The route module pulls requireAuth and the plugin-active gate from the middleware barrel; both
// are exercised in admin-gate.test.ts. Here they are pass-throughs so the QR logic is isolated.
vi.mock('../../../../middleware', async (importOriginal) => {
  const actual = (await importOriginal()) as Record<string, unknown>
  return {
    ...actual,
    requireAuth: () => async (_c: unknown, next: () => Promise<void>) => next(),
  }
})
vi.mock('../../../../middleware/plugin-middleware', () => ({
  isPluginActive: async () => true,
  invalidatePluginStatusCache: () => {},
}))

const { twoFactorAdminRoutes } = await import('../routes')

const VALID_URI =
  'otpauth://totp/SonicJS:admin@sonicjs.com?secret=JBSWY3DPEHPK3PXP&issuer=SonicJS&algorithm=SHA1&digits=6&period=30'

function makeApp() {
  const app = new Hono()
  app.use('*', async (c, next) => {
    c.env = { DB: {} } as never
    c.set('user' as never, { userId: 'u1', email: 'a@test.local', role: 'admin' } as never)
    await next()
  })
  app.route('/admin/two-factor', twoFactorAdminRoutes)
  return app
}

function postQr(uri: unknown) {
  return makeApp().request('/admin/two-factor/qr', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ uri }),
  })
}

describe('POST /admin/two-factor/qr', () => {
  it('returns an inline SVG for a TOTP enrolment URI', async () => {
    const res = await postQr(VALID_URI)
    expect(res.status).toBe(200)
    const { svg } = (await res.json()) as { svg: string }

    expect(svg.startsWith('<svg')).toBe(true)
    // The XML prolog is valid in a .svg file but meaningless inline in HTML, so it must be gone.
    expect(svg).not.toContain('<?xml')
    expect(svg).toContain('viewBox')
    // A real QR, not an empty scaffold: the module path has to carry actual geometry.
    expect(svg.length).toBeGreaterThan(1000)
    // Injected with innerHTML, so nothing executable may appear in it.
    expect(/<script/i.test(svg)).toBe(false)
  })

  it('encodes the URI it was given — a QR of the wrong string is worse than none', async () => {
    // Two different secrets must not produce the same image; that is the cheapest available
    // proof that the content actually reaches the encoder rather than a constant being returned.
    const a = (await (await postQr(VALID_URI)).json()) as { svg: string }
    const b = (await (
      await postQr(VALID_URI.replace('JBSWY3DPEHPK3PXP', 'MFRGGZDFMZTWQ2LK'))
    ).json()) as { svg: string }
    expect(a.svg).not.toEqual(b.svg)
  })

  it('refuses anything that is not an otpauth://totp/ URI', async () => {
    // Otherwise this is a "render any text as a QR, from your origin" service — a phishing
    // primitive, because a QR is unreadable to the human deciding whether to trust it.
    for (const bad of [
      'https://evil.test/steal',
      'otpauth://hotp/SonicJS:a@b.c?secret=X',
      'javascript:alert(1)',
      '',
      42,
      null,
      { uri: VALID_URI },
    ]) {
      const res = await postQr(bad)
      expect(res.status, `accepted ${JSON.stringify(bad)}`).toBe(400)
    }
  })

  it('refuses an over-long URI rather than encoding an unbounded payload', async () => {
    const res = await postQr(`${VALID_URI}&pad=${'x'.repeat(600)}`)
    expect(res.status).toBe(400)
  })

  it('refuses a request with no JSON body at all', async () => {
    const res = await makeApp().request('/admin/two-factor/qr', { method: 'POST' })
    expect(res.status).toBe(400)
  })
})

/**
 * ── Scannability ──
 *
 * Everything above passes whether or not the QR can actually be read, which is how a version that
 * rendered at 3.1 CSS px/module shipped green: the SVG is well-formed, encodes the URI, and refuses
 * bad input either way. Scannability is a property of CSS pixels PER MODULE, and the module count
 * grows with the URI — `issuer` is operator-configurable to 64 chars and Better Auth writes it into
 * the URI twice, so a long issuer plus a long email is a 69-module symbol where the shipped default
 * is 49.
 *
 * These tests pin the density directly, so a fixed size can never be reintroduced without failing.
 */
describe('POST /admin/two-factor/qr — scannability', () => {
  /** The floor below which phone cameras stop reliably decoding a screen. */
  const MIN_CSS_PX_PER_MODULE = 4

  function uriFor(issuer: string, email: string) {
    return (
      `otpauth://totp/${encodeURIComponent(`${issuer}:${email}`)}` +
      `?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=${encodeURIComponent(issuer)}` +
      `&algorithm=SHA1&digits=6&period=30`
    )
  }

  const CASES = [
    { name: 'shipped default issuer', uri: uriFor('SonicJS', 'admin@sonicjs.com') },
    { name: 'max-length issuer', uri: uriFor('A'.repeat(64), 'admin@sonicjs.com') },
    {
      name: 'max-length issuer + long email',
      uri: uriFor('A'.repeat(64), 'marketing.operations@some-long-company-name.example.com'),
    },
  ]

  async function render(uri: string) {
    const res = await postQr(uri)
    expect(res.status, `rejected a legitimate URI of ${uri.length} chars`).toBe(200)
    return (await res.json()) as { svg: string; renderPx: number; modulesAcross: number }
  }

  it.each(CASES)('stays above the scannable floor — $name', async ({ uri }) => {
    const { renderPx, modulesAcross } = await render(uri)
    expect(renderPx / modulesAcross).toBeGreaterThanOrEqual(MIN_CSS_PX_PER_MODULE)
  })

  it('sizes the <svg> element itself, not just the container', async () => {
    // A viewBox-only <svg> is sized entirely by its parent, which is what made the density an
    // invisible CSS detail. The painted size has to be on the element.
    const { svg, renderPx } = await render(CASES[0]!.uri)
    const openTag = svg.match(/<svg[^>]*>/)![0]
    expect(openTag).toContain(`width="${renderPx}"`)
    expect(openTag).toContain(`height="${renderPx}"`)
    // The viewBox must survive alongside them, or the scale is no longer uniform.
    expect(openTag).toMatch(/viewBox="0 0 \d+ \d+"/)
  })

  it('grows the rendered size as the symbol grows', async () => {
    // The invariant a hardcoded width violates: a denser symbol must come back physically larger.
    const [small, medium, large] = await Promise.all(CASES.map((c) => render(c.uri)))
    expect(medium!.modulesAcross).toBeGreaterThan(small!.modulesAcross)
    expect(large!.modulesAcross).toBeGreaterThan(medium!.modulesAcross)
    expect(medium!.renderPx).toBeGreaterThan(small!.renderPx)
    expect(large!.renderPx).toBeGreaterThan(medium!.renderPx)
  })

  it('keeps a 4-module quiet zone at every symbol size', async () => {
    // Measured in viewBox units off the module path, not assumed from the option we passed:
    // `padding` is in modules, so the border scales with the symbol and a regression here is
    // exactly the "won't scan on some phones" class of bug.
    for (const { uri, name } of CASES) {
      const { svg, modulesAcross } = await render(uri)
      const viewBox = Number(svg.match(/viewBox="0 0 (\d+)/)![1])
      const unitsPerModule = viewBox / modulesAcross
      const path = svg.match(/<path[^>]*d="([^"]+)"/)![1]!
      const xs = [...path.matchAll(/M(-?[\d.]+)/g)].map((m) => Number(m[1]))
      expect(Math.min(...xs) / unitsPerModule, `quiet zone wrong for ${name}`).toBeCloseTo(4, 1)
    }
  })
})
