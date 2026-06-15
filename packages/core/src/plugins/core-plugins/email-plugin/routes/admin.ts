/**
 * Admin routes for the v3 email-plugin — mounted at `/admin/email/*` (per Q1
 * Option A v3-init refactor). Two endpoints:
 *
 *   - `POST /admin/email/settings` — update the D1-stored plugin settings JSON
 *     (`fromEmail`, `fromName`, `replyTo`, `logoUrl`)
 *   - `POST /admin/email/test`     — send a test email confirming the CF
 *     Email Service binding is wired end-to-end
 *
 * Both routes are admin-only. Auth is enforced by `requireAuth()` middleware
 * applied to the sub-app (same pattern as adminPluginRoutes). Settings are stored
 * as a JSON string in `plugins.settings` for plugin id `'email'`.
 */
import { Hono } from 'hono'
import type { Bindings, Variables } from '../../../../app'
import { requireAuth } from '../../../../middleware'
import { getEmailService } from '../../../../services/email-service-singleton'
import { renderTestEmail } from '../templates/test-email'
import { EmailSettingsService } from '../services/settings.service'
import { SiteConfigService } from '../services/site-config.service'
import type { EmailSettings } from '../types'

interface SettingsBody {
  fromEmail?: string
  fromName?: string
  replyTo?: string
  logoUrl?: string
  cfAccountId?: string
  cfEmailApiToken?: string
}

interface TestBody {
  to?: string
}

export const adminRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

adminRoutes.use('*', requireAuth())

adminRoutes.post('/settings', async (c) => {
  const permissions = c.get('permissions')
  if (!permissions?.hasRole('admin')) {
    return c.json({ error: 'admin role required' }, 403)
  }

  const body = (await c.req.json().catch(() => null)) as SettingsBody | null
  if (!body || typeof body !== 'object') {
    return c.json({ error: 'invalid JSON body' }, 400)
  }

  const cleaned: EmailSettings = {}
  if (typeof body.fromEmail === 'string') cleaned.fromEmail = body.fromEmail.trim()
  if (typeof body.fromName === 'string') cleaned.fromName = body.fromName.trim()
  if (typeof body.replyTo === 'string') cleaned.replyTo = body.replyTo.trim()
  if (typeof body.logoUrl === 'string') cleaned.logoUrl = body.logoUrl.trim()
  if (typeof body.cfAccountId === 'string') cleaned.cfAccountId = body.cfAccountId.trim()
  if (typeof body.cfEmailApiToken === 'string') cleaned.cfEmailApiToken = body.cfEmailApiToken.trim()

  const json = JSON.stringify(cleaned)
  await c.env.DB
    .prepare(`UPDATE plugins SET settings = ?, updated_at = ? WHERE id = 'email'`)
    .bind(json, Date.now())
    .run()

  return c.json({ success: true, settings: cleaned })
})

adminRoutes.post('/test', async (c) => {
  const user = c.var.user
  const permissions = c.get('permissions')
  if (!permissions?.hasRole('admin')) {
    return c.json({ error: 'admin role required' }, 403)
  }

  const body = (await c.req.json().catch(() => null)) as TestBody | null
  const settings = new EmailSettingsService(c.env.DB)
  const settingsLoaded = await settings.load()
  const to = body?.to?.trim() || user?.email
  if (!to) {
    return c.json({ error: 'no recipient — pass `to` in body or attach a user with an email' }, 400)
  }

  const siteConfig = new SiteConfigService(c.env.DB, c.env)
  const { siteName } = await siteConfig.load()

  const { subject, html, text } = renderTestEmail({ siteName })

  try {
    const result = await getEmailService().send({
      to,
      subject,
      html,
      text,
      from: settingsLoaded.fromEmail,
      fromName: settingsLoaded.fromName,
      replyTo: settingsLoaded.replyTo,
      purpose: 'test',
      userId: user?.userId,
      templateName: 'admin.test',
    })

    return c.json({
      success: result.status === 'submitted',
      result,
    })
  } catch (err) {
    // Validation errors (missing from, etc.) — return 400 with detail.
    return c.json(
      {
        error: err instanceof Error ? err.message : String(err),
      },
      400,
    )
  }
})
