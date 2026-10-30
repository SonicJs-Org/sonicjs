/**
 * Public invitation join routes — mounted at /join/invite (NO auth middleware).
 *
 * Handles the full invitation acceptance flow for unauthenticated users:
 *   GET  /join/invite?token=X          → route to register or sign-in page
 *   GET  /join/invite/register?token=X → registration form
 *   POST /join/invite/register          → create user + accept invitation
 *   POST /join/invite/sign-in           → sign in + accept invitation
 *
 * The accept URL in invitation emails points here instead of /admin/tenants/invitations/accept
 * because /admin/* requires authentication at the app level.
 *
 * Already-authenticated users who click the accept link are handled by the admin route
 * at GET /admin/tenants/invitations/accept (existing behaviour, unchanged).
 */
import { Hono } from 'hono'
import type { D1Database, KVNamespace } from '@cloudflare/workers-types'
import { TenantService } from '../services/tenant-service'
import { AuthManager } from '../../../../middleware/auth'
import { renderInvitationJoinPage, renderInvitationErrorPage } from '../templates/invitation-join.template'
import { createAuth } from '../../../../auth/config'
import { MAX_PASSWORD_LENGTH } from '../../../../services/auth-validation'

type Bindings = { DB: D1Database; KV: KVNamespace; JWT_SECRET?: string }
type Variables = {
  user?: { userId: string; email: string; role: string }
  appVersion?: string
}

/** Look up a pending invitation row; returns null + error string if invalid/expired. */
async function lookupPendingInvitation(
  db: D1Database,
  token: string,
): Promise<{ inv: { id: string; email: string; role: string; tenantName: string; tenantSlug: string } } | { error: string }> {
  if (!token) return { error: 'No invitation token provided.' }
  try {
    const row = await db.prepare(`
      SELECT i.id, i.email, i.role, i.status, i.expires_at, t.name as tenant_name, t.slug as tenant_slug
      FROM auth_tenant_invitation i
      JOIN auth_tenant t ON t.id = i.tenant_id
      WHERE i.id = ?
    `).bind(token).first() as {
      id?: string; email?: string; role?: string; status?: string
      expires_at?: number; tenant_name?: string; tenant_slug?: string
    } | null

    if (!row?.id) return { error: 'Invitation not found.' }
    if (row.status !== 'pending') return { error: 'This invitation has already been used or revoked.' }
    if (Number(row.expires_at) < Date.now()) return { error: 'This invitation has expired.' }

    return {
      inv: {
        id: row.id,
        email: row.email!,
        role: row.role || 'viewer',
        tenantName: row.tenant_name || row.tenant_slug || 'Unknown',
        tenantSlug: row.tenant_slug!,
      },
    }
  } catch {
    return { error: 'Failed to look up invitation.' }
  }
}

/** Set Better Auth session cookie(s) from a successful sign-in response. */
function copyBaCookies(baRes: Response, responseHeaders: Headers): void {
  const raw = baRes.headers.get('set-cookie')
  if (raw) {
    responseHeaders.append('Set-Cookie', raw)
    return
  }
  if ((baRes.headers as any).getSetCookie) {
    for (const sc of (baRes.headers as any).getSetCookie()) {
      responseHeaders.append('Set-Cookie', sc)
    }
  }
}

export function createJoinRoutes(): Hono<{ Bindings: Bindings; Variables: Variables }> {
  const routes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

  // ─── GET /join/invite — route to register or sign-in page ────────────────────
  routes.get('/', async (c) => {
    const db = c.env.DB
    const token = c.req.query('token') ?? ''
    const version = c.get('appVersion')

    // If already signed in, hand off to the admin accept route.
    const user = c.get('user')
    if (user) {
      return c.redirect(`/admin/tenants/invitations/accept?token=${encodeURIComponent(token)}`)
    }

    const result = await lookupPendingInvitation(db, token)
    if ('error' in result) return c.html(renderInvitationErrorPage(result.error, version), 400)

    const { inv } = result
    const existingUser = await db.prepare('SELECT id FROM auth_user WHERE LOWER(email) = ?')
      .bind(inv.email.toLowerCase()).first()

    return c.redirect(
      existingUser
        ? `/join/invite/sign-in?token=${encodeURIComponent(token)}`
        : `/join/invite/register?token=${encodeURIComponent(token)}`,
    )
  })

  // ─── GET /join/invite/register — registration form ───────────────────────────
  routes.get('/register', async (c) => {
    const db = c.env.DB
    const token = c.req.query('token') ?? ''
    const version = c.get('appVersion')

    const user = c.get('user')
    if (user) return c.redirect(`/admin/tenants/invitations/accept?token=${encodeURIComponent(token)}`)

    const result = await lookupPendingInvitation(db, token)
    if ('error' in result) return c.html(renderInvitationErrorPage(result.error, version), 400)

    const { inv } = result
    return c.html(renderInvitationJoinPage({
      tenantName: inv.tenantName, tenantSlug: inv.tenantSlug, role: inv.role,
      email: inv.email, token, mode: 'register', version,
    }))
  })

  // ─── POST /join/invite/register — create user + accept ───────────────────────
  routes.post('/register', async (c) => {
    const db = c.env.DB
    const version = c.get('appVersion')
    const form = await c.req.formData()
    const token = String(form.get('token') ?? '')
    const firstName = String(form.get('firstName') ?? '').trim()
    const lastName = String(form.get('lastName') ?? '').trim()
    const password = String(form.get('password') ?? '')

    const result = await lookupPendingInvitation(db, token)
    if ('error' in result) return c.html(renderInvitationErrorPage(result.error, version), 400)

    const { inv } = result

    const rerender = (error: string) =>
      c.html(renderInvitationJoinPage({
        tenantName: inv.tenantName, tenantSlug: inv.tenantSlug, role: inv.role,
        email: inv.email, token, mode: 'register', error, version,
      }), 400)

    if (!firstName) return rerender('First name is required.')
    if (!lastName) return rerender('Last name is required.')
    if (password.length < 8) return rerender('Password must be at least 8 characters.')
    if (password.length > MAX_PASSWORD_LENGTH) return rerender(`Password must be at most ${MAX_PASSWORD_LENGTH} characters.`)

    // Ensure no existing account for this email.
    const existing = await db.prepare('SELECT id FROM auth_user WHERE LOWER(email) = ?')
      .bind(inv.email.toLowerCase()).first()
    if (existing) return rerender('An account with this email already exists. Please sign in instead.')

    try {
      // 1. Create user + credential row (mirrors register/form logic).
      const userId = crypto.randomUUID()
      const passwordHash = await AuthManager.hashPassword(password)
      const now = Date.now()
      const nowSec = Math.floor(now / 1000)

      await db.batch([
        db.prepare(
          `INSERT INTO auth_user (id, email, first_name, last_name, password_hash, role, is_active, email_verified, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, 'viewer', 1, 1, ?, ?)`
        ).bind(userId, inv.email.toLowerCase(), firstName, lastName, passwordHash, now, now),
        db.prepare(
          `INSERT OR IGNORE INTO auth_account (id, user_id, account_id, provider_id, password, created_at, updated_at)
           VALUES (?, ?, ?, 'credential', ?, ?, ?)`
        ).bind(`cred-${userId}`, userId, userId, passwordHash, nowSec, nowSec),
      ])

      // 2. Accept the invitation (adds tenant member row).
      await new TenantService(db).acceptInvitation(token, userId, inv.email)

      // 3. Sign in via Better Auth to get a proper session cookie.
      const auth = createAuth(c.env as any)
      const origin = new URL(c.req.url).origin
      const baReq = new Request(`${origin}/auth/sign-in/email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Origin': origin },
        body: JSON.stringify({ email: inv.email.toLowerCase(), password }),
      })
      const baRes = await auth.handler(baReq)

      const headers = new Headers({ Location: '/admin?message=Welcome! You have joined ' + encodeURIComponent(inv.tenantName) })
      if (baRes.ok) copyBaCookies(baRes, headers)
      return new Response(null, { status: 302, headers })
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Registration failed'
      return rerender(msg)
    }
  })

  // ─── GET /join/invite/sign-in — sign-in form for existing users ───────────────
  routes.get('/sign-in', async (c) => {
    const db = c.env.DB
    const token = c.req.query('token') ?? ''
    const version = c.get('appVersion')

    const user = c.get('user')
    if (user) return c.redirect(`/admin/tenants/invitations/accept?token=${encodeURIComponent(token)}`)

    const result = await lookupPendingInvitation(db, token)
    if ('error' in result) return c.html(renderInvitationErrorPage(result.error, version), 400)

    const { inv } = result
    return c.html(renderInvitationJoinPage({
      tenantName: inv.tenantName, tenantSlug: inv.tenantSlug, role: inv.role,
      email: inv.email, token, mode: 'sign-in', version,
    }))
  })

  // ─── POST /join/invite/sign-in — sign in existing user + accept ───────────────
  routes.post('/sign-in', async (c) => {
    const db = c.env.DB
    const version = c.get('appVersion')
    const form = await c.req.formData()
    const token = String(form.get('token') ?? '')
    const password = String(form.get('password') ?? '')

    const result = await lookupPendingInvitation(db, token)
    if ('error' in result) return c.html(renderInvitationErrorPage(result.error, version), 400)

    const { inv } = result

    const rerender = (error: string) =>
      c.html(renderInvitationJoinPage({
        tenantName: inv.tenantName, tenantSlug: inv.tenantSlug, role: inv.role,
        email: inv.email, token, mode: 'sign-in', error, version,
      }), 400)

    try {
      // Sign in via Better Auth.
      const auth = createAuth(c.env as any)
      const origin = new URL(c.req.url).origin
      const baReq = new Request(`${origin}/auth/sign-in/email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Origin': origin },
        body: JSON.stringify({ email: inv.email.toLowerCase(), password }),
      })
      const baRes = await auth.handler(baReq)

      if (!baRes.ok) return rerender('Incorrect password. Please try again.')

      // Get the user ID from the BA session to accept the invitation.
      const baBody = await baRes.json() as { user?: { id?: string } }
      const userId = baBody?.user?.id
      if (!userId) return rerender('Sign-in succeeded but could not read user ID.')

      await new TenantService(db).acceptInvitation(token, userId, inv.email)

      const headers = new Headers({ Location: '/admin?message=Welcome! You have joined ' + encodeURIComponent(inv.tenantName) })
      copyBaCookies(baRes, headers)
      return new Response(null, { status: 302, headers })
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Sign-in failed'
      return rerender(msg)
    }
  })

  return routes
}
