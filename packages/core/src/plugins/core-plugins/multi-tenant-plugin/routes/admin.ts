/**
 * Multi-tenant plugin admin routes — mounted at /admin/tenants.
 *
 * Self-gated: routes mount statically (deactivation never unmounts routes), so every handler
 * checks the plugin's activation state and renders a notice page / 403 while inactive.
 */
import { Hono } from 'hono'
import { setCookie } from 'hono/cookie'
import { z } from 'zod'
import type { D1Database, KVNamespace } from '@cloudflare/workers-types'
import { requireAuth } from '../../../../middleware/auth'
import { TENANT_COOKIE, MULTI_TENANT_PLUGIN_ID } from '../../../../middleware/tenant'
import { PluginService } from '../../../../services/plugin-service'
import { TenantService, isValidMemberRole } from '../services/tenant-service'
import { renderTenantsList, renderTenantsInactive } from '../templates/tenants-list.template'
import { renderTenantForm } from '../templates/tenant-form.template'
import { renderTenantMembers } from '../templates/tenant-members.template'
import { renderUserMemberships } from '../templates/user-memberships.template'
import { renderRoleUsage } from '../templates/role-usage.template'
import { getEmailService, hasEmailService } from '../../../../services/email/email-service-singleton'
import { escapeHtml } from '../../../../utils/sanitize'

type Bindings = { DB: D1Database; KV: KVNamespace }
type Variables = {
  user?: { userId: string; email: string; role: string; isSuperAdmin?: boolean; exp: number; iat: number }
  tenantId?: string
  appVersion?: string
}

const tenantFormSchema = z.object({
  name: z.string().min(1, 'Name is required').max(100),
  slug: z.string().min(1, 'Slug is required').max(63).optional(),
  domain: z.string().max(253).optional(),
  status: z.enum(['active', 'inactive']).optional(),
  notes: z.string().max(2000).optional(),
})

function userShape(user: any) {
  return user ? { name: user.email, email: user.email, role: user.role } : undefined
}

function renderInviteEmail(acceptUrl: string, slug: string, role: string): string {
  const s = escapeHtml(slug)
  const r = escapeHtml(role)
  const url = escapeHtml(acceptUrl)
  return `<div style="font-family:sans-serif;max-width:600px">
    <h2>You're invited to ${s}</h2>
    <p>You've been invited to the <strong>${s}</strong> workspace as <strong>${r}</strong>.</p>
    <p>Sign in with this email address, then open the link below to join:</p>
    <p><a href="${url}" style="background:#465FFF;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none">Accept invitation</a></p>
    <p style="color:#666;font-size:12px">Or copy this link: ${url}</p>
  </div>`
}

function zodToFieldErrors(error: z.ZodError): Record<string, string[]> {
  const errors: Record<string, string[]> = {}
  error.issues.forEach(e => {
    const f = String(e.path[0] ?? 'form')
    errors[f] = [...(errors[f] ?? []), e.message]
  })
  return errors
}

async function isMultiTenantActive(db: D1Database): Promise<boolean> {
  try {
    const plugin = await new PluginService(db).getPlugin(MULTI_TENANT_PLUGIN_ID)
    return plugin?.status === 'active'
  } catch {
    return false
  }
}

export function createTenantAdminRoutes(): Hono<{ Bindings: Bindings; Variables: Variables }> {
  const routes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

  routes.use('*', requireAuth())
  routes.use('*', async (c, next) => {
    const user = c.get('user')
    if (user?.role !== 'admin') {
      return c.json({ error: 'Admin access required' }, 403)
    }
    return next()
  })

  // ─── Switch active tenant (sidebar switcher + list-page Switch buttons) ────
  routes.post('/switch', async (c) => {
    const db = c.env.DB
    if (!(await isMultiTenantActive(db))) return c.json({ error: 'Multi-tenant plugin is not active' }, 403)

    const form = await c.req.formData()
    const slug = String(form.get('tenant') ?? '').trim().toLowerCase()
    const redirect = String(form.get('redirect') ?? '')

    const svc = new TenantService(db)
    const tenant = await svc.getTenantBySlug(slug)
    if (!tenant || tenant.status !== 'active') {
      return c.json({ error: 'Unknown or inactive tenant' }, 400)
    }

    // Membership gate: a user may only switch into tenants they belong to ('default' is open).
    // Platform super-admins bypass the gate (access every tenant).
    const user = c.get('user')
    if (!user) return c.json({ error: 'Unauthorized' }, 401)
    if (!user.isSuperAdmin && !(await svc.isMember(user.userId, slug))) {
      return c.json({ error: 'You are not a member of this tenant' }, 403)
    }

    setCookie(c, TENANT_COOKIE, slug, {
      path: '/',
      httpOnly: true,
      sameSite: 'Lax',
      maxAge: 60 * 60 * 24 * 365,
    })

    let target = redirect.startsWith('/') && !redirect.startsWith('//') ? redirect : '/admin'
    // Detail/edit pages are tenant-specific; send back to the list instead.
    if (/^\/admin\/content\/.+/.test(target)) target = '/admin/content'
    return c.redirect(target)
  })

  // ─── Accept an invitation ─────────────────────────────────────────────────────
  // Registered before the /:slug routes so 'invitations' is never read as a tenant slug. The accept
  // is gated on the signed-in user's email matching the invited email (see acceptInvitation).
  routes.get('/invitations/accept', async (c) => {
    const db = c.env.DB
    if (!(await isMultiTenantActive(db))) return c.json({ error: 'Multi-tenant plugin is not active' }, 403)
    const user = c.get('user')
    if (!user) return c.redirect('/auth/login')
    const token = c.req.query('token') ?? ''
    try {
      const { slug } = await new TenantService(db).acceptInvitation(token, user.userId, user.email)
      return c.redirect(`/admin/tenants/${slug}/members?message=Invitation accepted`)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to accept invitation'
      return c.redirect(`/admin/tenants?message=${encodeURIComponent(message)}&type=error`)
    }
  })

  // ─── User email search for datalist autocomplete ────────────────────────────
  routes.get('/users/search', async (c) => {
    const db = c.env.DB
    if (!(await isMultiTenantActive(db))) return c.text('', 200)
    const q = (c.req.query('email') ?? c.req.query('q') ?? '').trim().toLowerCase()
    if (!q) return c.text('', 200)
    const { results } = await db.prepare(
      `SELECT email FROM auth_user WHERE LOWER(email) LIKE ? LIMIT 10`
    ).bind(`%${q}%`).all()
    const options = (results ?? []).map((r: any) => `<option value="${escapeHtml(r.email as string)}">`).join('')
    return c.html(options)
  })

  // ─── User-centric memberships (registered before /:slug; 'users' is reserved) ──
  routes.get('/users/:userId', async (c) => {
    const db = c.env.DB
    const cur = c.get('user')
    const version = c.get('appVersion')
    if (!(await isMultiTenantActive(db))) {
      return c.html(renderTenantsInactive({ user: userShape(cur), version }))
    }
    const userId = c.req.param('userId')
    const target = await db.prepare('SELECT id, email FROM auth_user WHERE id = ?').bind(userId).first() as { id?: string; email?: string } | null
    if (!target?.id) return c.redirect('/admin/users?message=User not found&type=error')

    const svc = new TenantService(db)
    const [memberships, allTenants] = await Promise.all([svc.listUserMemberships(userId), svc.listTenants()])
    const memberSlugs = new Set(memberships.map((m) => m.slug))
    const availableTenants = allTenants
      .filter((t) => t.status === 'active' && !memberSlugs.has(t.slug))
      .map((t) => ({ slug: t.slug, name: t.name }))
    const messageType = c.req.query('type') === 'error' ? 'error' as const : 'success' as const
    return c.html(renderUserMemberships({
      userId, userEmail: target.email ?? userId, memberships, availableTenants,
      user: userShape(cur), version, message: c.req.query('message'), messageType,
    }))
  })

  routes.post('/users/:userId/memberships', async (c) => {
    const db = c.env.DB
    const userId = c.req.param('userId')
    if (!(await isMultiTenantActive(db))) return c.json({ error: 'Multi-tenant plugin is not active' }, 403)
    try {
      const form = await c.req.formData()
      const slug = String(form.get('slug') ?? '').trim().toLowerCase()
      const role = String(form.get('role') ?? 'viewer')
      const redirectTo = String(form.get('_redirect') ?? '') || `/admin/tenants/users/${userId}`
      if (!isValidMemberRole(role)) throw new Error(`Invalid role '${role}'`)
      const target = await db.prepare('SELECT email FROM auth_user WHERE id = ?').bind(userId).first() as { email?: string } | null
      if (!target) throw new Error('User not found')
      const svc = new TenantService(db)
      if (!(await svc.getTenantBySlug(slug))) throw new Error('Tenant not found')
      if (await svc.isMember(userId, slug)) throw new Error(`Already a member of '${slug}'`)
      await svc.addMember(slug, userId, role, target.email ?? null)
      return c.redirect(`${redirectTo}?message=Added to ${encodeURIComponent(slug)}`)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to add membership'
      return c.redirect(`/admin/tenants/users/${userId}?message=${encodeURIComponent(message)}&type=error`)
    }
  })

  routes.post('/users/:userId/memberships/:slug/role', async (c) => {
    const db = c.env.DB
    const userId = c.req.param('userId')
    const slug = c.req.param('slug')
    if (!(await isMultiTenantActive(db))) return c.json({ error: 'Multi-tenant plugin is not active' }, 403)
    try {
      const form = await c.req.formData()
      const role = String(form.get('role') ?? '')
      const redirectTo = String(form.get('_redirect') ?? '') || `/admin/tenants/users/${userId}`
      await new TenantService(db).setMemberRole(slug, userId, role)
      return c.redirect(`${redirectTo}?message=Role updated`)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to update role'
      return c.redirect(`/admin/tenants/users/${userId}?message=${encodeURIComponent(message)}&type=error`)
    }
  })

  routes.post('/users/:userId/memberships/:slug/delete', async (c) => {
    const db = c.env.DB
    const userId = c.req.param('userId')
    const slug = c.req.param('slug')
    if (!(await isMultiTenantActive(db))) return c.json({ error: 'Multi-tenant plugin is not active' }, 403)
    try {
      const form = await c.req.formData()
      const redirectTo = String(form.get('_redirect') ?? '') || `/admin/tenants/users/${userId}`
      await new TenantService(db).removeMember(slug, userId)
      return c.redirect(`${redirectTo}?message=Removed from ${encodeURIComponent(slug)}`)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to remove membership'
      return c.redirect(`/admin/tenants/users/${userId}?message=${encodeURIComponent(message)}&type=error`)
    }
  })

  // ─── Role usage (read-only): where a role is assigned across tenants ──────────
  routes.get('/roles/:roleName', async (c) => {
    const db = c.env.DB
    const cur = c.get('user')
    const version = c.get('appVersion')
    if (!(await isMultiTenantActive(db))) {
      return c.html(renderTenantsInactive({ user: userShape(cur), version }))
    }
    const roleName = c.req.param('roleName')
    const assignments = await new TenantService(db).listAssignmentsByRole(roleName)
    return c.html(renderRoleUsage({ roleName, assignments, user: userShape(cur), version }))
  })

  // ─── List ───────────────────────────────────────────────────────────────────
  routes.get('/', async (c) => {
    const db = c.env.DB
    const user = c.get('user')
    const version = c.get('appVersion')
    if (!(await isMultiTenantActive(db))) {
      return c.html(renderTenantsInactive({ user: userShape(user), version }))
    }

    const svc = new TenantService(db)
    await svc.ensureDefaultTenant()
    const tenants = await svc.listTenants()

    const [docRes, memberRes] = await db.batch([
      db.prepare('SELECT tenant_id, COUNT(*) as count FROM documents WHERE deleted_at IS NULL GROUP BY tenant_id'),
      db.prepare('SELECT t.slug, COUNT(m.id) as count FROM auth_tenant t LEFT JOIN auth_tenant_member m ON m.tenant_id = t.id GROUP BY t.id'),
    ])
    const counts = new Map((docRes?.results ?? []).map((r: any) => [r.tenant_id, r.count as number]))
    const memberCounts = new Map((memberRes?.results ?? []).map((r: any) => [r.slug, r.count as number]))

    const messageType = c.req.query('type') === 'error' ? 'error' as const : 'success' as const
    return c.html(renderTenantsList({
      tenants: tenants.map(t => ({ ...t, documentCount: counts.get(t.slug) ?? 0, memberCount: memberCounts.get(t.slug) ?? 0 })),
      currentTenantId: c.get('tenantId') ?? 'default',
      user: userShape(user),
      version,
      message: c.req.query('message'),
      messageType,
    }))
  })

  // ─── New form ───────────────────────────────────────────────────────────────
  routes.get('/new', async (c) => {
    const db = c.env.DB
    const user = c.get('user')
    const version = c.get('appVersion')
    if (!(await isMultiTenantActive(db))) {
      return c.html(renderTenantsInactive({ user: userShape(user), version }))
    }
    return c.html(renderTenantForm({ isEdit: false, user: userShape(user), version }))
  })

  // ─── Create ─────────────────────────────────────────────────────────────────
  routes.post('/', async (c) => {
    const db = c.env.DB
    const user = c.get('user')
    const version = c.get('appVersion')
    if (!(await isMultiTenantActive(db))) return c.json({ error: 'Multi-tenant plugin is not active' }, 403)

    let formEntries: Record<string, unknown> = {}
    try {
      const form = await c.req.formData()
      formEntries = Object.fromEntries(form.entries())
      const validated = tenantFormSchema.parse(formEntries)
      if (!validated.slug) throw new z.ZodError([{ code: 'custom', message: 'Slug is required', path: ['slug'] }])

      const svc = new TenantService(db)
      await svc.createTenant({
        name: validated.name,
        slug: validated.slug,
        domain: validated.domain || null,
        notes: validated.notes,
      })
      // Auto-enroll the creator as the tenant 'admin' (a role name the document ACL understands) so
      // they get full per-tenant access and can immediately switch into / manage the tenant.
      if (user) await svc.addMember(validated.slug, user.userId, 'admin', user.email)
      return c.redirect('/admin/tenants?message=Tenant created successfully')
    } catch (error) {
      const tenant = { name: String(formEntries.name ?? ''), slug: String(formEntries.slug ?? ''), domain: String(formEntries.domain ?? ''), notes: String(formEntries.notes ?? '') }
      if (error instanceof z.ZodError) {
        return c.html(renderTenantForm({ isEdit: false, tenant, user: userShape(user), version, errors: zodToFieldErrors(error), message: 'Please correct the errors below', messageType: 'error' }))
      }
      const message = error instanceof Error ? error.message : 'Failed to create tenant'
      return c.html(renderTenantForm({ isEdit: false, tenant, user: userShape(user), version, message, messageType: 'error' }))
    }
  })

  // ─── Edit form ──────────────────────────────────────────────────────────────
  routes.get('/:slug/edit', async (c) => {
    const db = c.env.DB
    const user = c.get('user')
    const version = c.get('appVersion')
    if (!(await isMultiTenantActive(db))) {
      return c.html(renderTenantsInactive({ user: userShape(user), version }))
    }

    const tenant = await new TenantService(db).getTenantBySlug(c.req.param('slug'))
    if (!tenant) return c.redirect('/admin/tenants?message=Tenant not found&type=error')
    return c.html(renderTenantForm({ tenant, isEdit: true, user: userShape(user), version }))
  })

  // ─── Update ─────────────────────────────────────────────────────────────────
  routes.post('/:slug', async (c) => {
    const db = c.env.DB
    const user = c.get('user')
    const version = c.get('appVersion')
    const slug = c.req.param('slug')
    if (!(await isMultiTenantActive(db))) return c.json({ error: 'Multi-tenant plugin is not active' }, 403)

    const svc = new TenantService(db)
    try {
      const form = await c.req.formData()
      const validated = tenantFormSchema.parse(Object.fromEntries(form.entries()))
      await svc.updateTenant(slug, {
        name: validated.name,
        domain: validated.domain || null,
        status: validated.status,
        notes: validated.notes,
      })
      return c.redirect('/admin/tenants?message=Tenant updated successfully')
    } catch (error) {
      const tenant = (await svc.getTenantBySlug(slug)) ?? { slug }
      if (error instanceof z.ZodError) {
        return c.html(renderTenantForm({ tenant, isEdit: true, user: userShape(user), version, errors: zodToFieldErrors(error), message: 'Please correct the errors below', messageType: 'error' }))
      }
      const message = error instanceof Error ? error.message : 'Failed to update tenant'
      return c.html(renderTenantForm({ tenant, isEdit: true, user: userShape(user), version, message, messageType: 'error' }))
    }
  })

  // ─── Delete ─────────────────────────────────────────────────────────────────
  routes.post('/:slug/delete', async (c) => {
    const db = c.env.DB
    const slug = c.req.param('slug')
    if (!(await isMultiTenantActive(db))) return c.json({ error: 'Multi-tenant plugin is not active' }, 403)

    try {
      await new TenantService(db).deleteTenant(slug)
      return c.redirect('/admin/tenants?message=Tenant deleted successfully')
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to delete tenant'
      return c.redirect(`/admin/tenants?message=${encodeURIComponent(message)}&type=error`)
    }
  })

  // ─── Members: list ────────────────────────────────────────────────────────────
  routes.get('/:slug/members', async (c) => {
    const db = c.env.DB
    const user = c.get('user')
    const version = c.get('appVersion')
    if (!(await isMultiTenantActive(db))) {
      return c.html(renderTenantsInactive({ user: userShape(user), version }))
    }
    const slug = c.req.param('slug')
    const svc = new TenantService(db)
    const tenant = await svc.getTenantBySlug(slug)
    if (!tenant) return c.redirect('/admin/tenants?message=Tenant not found&type=error')

    const [members, invitations] = await Promise.all([svc.listMembers(slug), svc.listInvitations(slug)])
    const qt = c.req.query('type')
    const messageType = qt === 'error' ? 'error' as const : qt === 'warning' ? 'warning' as const : 'success' as const
    return c.html(renderTenantMembers({
      slug, tenantName: tenant.name, members, invitations,
      user: userShape(user), version,
      message: c.req.query('message'), messageType,
      retryInvitationId: c.req.query('retry_invitation'),
    }))
  })

  // ─── Members: add by email ──────────────────────────────────────────────────────
  routes.post('/:slug/members', async (c) => {
    const db = c.env.DB
    const slug = c.req.param('slug')
    if (!(await isMultiTenantActive(db))) return c.json({ error: 'Multi-tenant plugin is not active' }, 403)
    try {
      const form = await c.req.formData()
      const email = String(form.get('email') ?? '')
      const role = String(form.get('role') ?? 'viewer')
      await new TenantService(db).addMemberByEmail(slug, email, role)
      return c.redirect(`/admin/tenants/${slug}/members?message=Member added`)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to add member'
      return c.redirect(`/admin/tenants/${slug}/members?message=${encodeURIComponent(message)}&type=error`)
    }
  })

  // ─── Members: change role ─────────────────────────────────────────────────────────
  routes.post('/:slug/members/:userId/role', async (c) => {
    const db = c.env.DB
    const slug = c.req.param('slug')
    const userId = c.req.param('userId')
    if (!(await isMultiTenantActive(db))) return c.json({ error: 'Multi-tenant plugin is not active' }, 403)
    try {
      const form = await c.req.formData()
      const role = String(form.get('role') ?? '')
      await new TenantService(db).setMemberRole(slug, userId, role)
      return c.redirect(`/admin/tenants/${slug}/members?message=Role updated`)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to update role'
      return c.redirect(`/admin/tenants/${slug}/members?message=${encodeURIComponent(message)}&type=error`)
    }
  })

  // ─── Members: remove ──────────────────────────────────────────────────────────────
  routes.post('/:slug/members/:userId/delete', async (c) => {
    const db = c.env.DB
    const slug = c.req.param('slug')
    const userId = c.req.param('userId')
    if (!(await isMultiTenantActive(db))) return c.json({ error: 'Multi-tenant plugin is not active' }, 403)
    try {
      await new TenantService(db).removeMember(slug, userId)
      return c.redirect(`/admin/tenants/${slug}/members?message=Member removed`)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to remove member'
      return c.redirect(`/admin/tenants/${slug}/members?message=${encodeURIComponent(message)}&type=error`)
    }
  })

  // ─── Invitations: create ──────────────────────────────────────────────────────
  routes.post('/:slug/invitations', async (c) => {
    const db = c.env.DB
    const slug = c.req.param('slug')
    const user = c.get('user')
    if (!(await isMultiTenantActive(db))) return c.json({ error: 'Multi-tenant plugin is not active' }, 403)
    try {
      const form = await c.req.formData()
      const email = String(form.get('email') ?? '')
      const role = String(form.get('role') ?? 'viewer')
      const token = await new TenantService(db).createInvitation(slug, email, role, user?.userId ?? null)

      // Best-effort email delivery of the accept link. The link is also shown in the UI, so a
      // missing/failed mailer never blocks the invite (mirrors the password-reset flow).
      const origin = c.req.header('origin') || new URL(c.req.url).origin
      const acceptUrl = `${origin}/join/invite?token=${encodeURIComponent(token)}`
      let note: string
      let noteType = ''
      const svc2 = hasEmailService() ? getEmailService() : null
      const hasRealProvider = !!svc2 && svc2.getProviderName() !== 'console'
      if (hasRealProvider) {
        const result = await svc2!.send({
          to: email.trim(),
          subject: `You're invited to the ${slug} workspace`,
          flow: 'tenant-invitation',
          html: renderInviteEmail(acceptUrl, slug, role),
          text: `You've been invited to '${slug}' as ${role}. Sign in with this email and accept: ${acceptUrl}`,
        })
        if (result.ok) {
          note = 'Invitation created and emailed'
        } else {
          console.error('Failed to send invitation email:', result.error)
          note = 'Invitation created — email failed to send, share the accept link manually'
          noteType = 'warning'
        }
      } else {
        note = 'Invitation created — no email plugin active, share the accept link manually'
        noteType = 'warning'
      }
      const typeParam = noteType ? `&type=${noteType}` : ''
      const retryParam = noteType === 'warning' && hasRealProvider ? `&retry_invitation=${encodeURIComponent(token)}` : ''
      return c.redirect(`/admin/tenants/${slug}/members?message=${encodeURIComponent(note)}${typeParam}${retryParam}`)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to create invitation'
      return c.redirect(`/admin/tenants/${slug}/members?message=${encodeURIComponent(message)}&type=error`)
    }
  })

  // ─── Invitations: resend email ────────────────────────────────────────────────
  routes.post('/:slug/invitations/:id/resend', async (c) => {
    const db = c.env.DB
    const slug = c.req.param('slug')
    const id = c.req.param('id')
    if (!(await isMultiTenantActive(db))) return c.json({ error: 'Multi-tenant plugin is not active' }, 403)
    try {
      const inv = await db.prepare(
        `SELECT i.id, i.email, i.role FROM auth_tenant_invitation i
         JOIN auth_tenant t ON t.id = i.tenant_id
         WHERE i.id = ? AND t.slug = ? AND i.status = 'pending'`
      ).bind(id, slug).first() as { id: string; email: string; role: string } | null
      if (!inv) throw new Error('Invitation not found or already used')

      const svc2 = hasEmailService() ? getEmailService() : null
      const hasRealProvider = !!svc2 && svc2.getProviderName() !== 'console'
      if (!hasRealProvider) throw new Error('No email plugin active')

      const origin = c.req.header('origin') || new URL(c.req.url).origin
      const acceptUrl = `${origin}/join/invite?token=${encodeURIComponent(inv.id)}`
      const result = await svc2!.send({
        to: inv.email,
        subject: `You're invited to the ${slug} workspace`,
        flow: 'tenant-invitation',
        html: renderInviteEmail(acceptUrl, slug, inv.role),
        text: `You've been invited to '${slug}' as ${inv.role}. Sign in with this email and accept: ${acceptUrl}`,
      })
      if (!result.ok) throw new Error(result.error ?? 'Send failed')
      return c.redirect(`/admin/tenants/${slug}/members?message=Invitation email sent to ${encodeURIComponent(inv.email)}`)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to resend invitation'
      return c.redirect(`/admin/tenants/${slug}/members?message=${encodeURIComponent(message)}&type=error`)
    }
  })

  // ─── Invitations: revoke ──────────────────────────────────────────────────────
  routes.post('/:slug/invitations/:id/revoke', async (c) => {
    const db = c.env.DB
    const slug = c.req.param('slug')
    const id = c.req.param('id')
    if (!(await isMultiTenantActive(db))) return c.json({ error: 'Multi-tenant plugin is not active' }, 403)
    try {
      await new TenantService(db).revokeInvitation(slug, id)
      return c.redirect(`/admin/tenants/${slug}/members?message=Invitation revoked`)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to revoke invitation'
      return c.redirect(`/admin/tenants/${slug}/members?message=${encodeURIComponent(message)}&type=error`)
    }
  })

  return routes
}
