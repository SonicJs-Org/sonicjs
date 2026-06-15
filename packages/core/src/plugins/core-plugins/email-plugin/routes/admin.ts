/**
 * Admin routes for the v3 email-plugin — mounted at `/admin/email/*`.
 *
 *   - `POST /admin/email/settings` — update D1-stored plugin settings JSON
 *   - `POST /admin/email/test`     — send a test email end-to-end
 *
 * Adapted from mmcintosh/sonicjs-infowall-merge:
 * - Auth check uses `c.get('user')?.role` (our `Variables.user` shape)
 * - `getEmailService()` path corrected to `services/email/email-service-singleton`
 * - `send()` call uses our `EmailMessage` shape (flow not purpose)
 * - `result.ok` instead of `result.status === 'submitted'`
 */
import { Hono } from 'hono'
import type { Bindings, Variables } from '../../../../app'
import { requireAuth } from '../../../../middleware'
import { getEmailService } from '../../../../services/email/email-service-singleton'
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
  if (c.get('user')?.role !== 'admin') {
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
  const user = c.get('user')
  if (user?.role !== 'admin') {
    return c.json({ error: 'admin role required' }, 403)
  }

  const body = (await c.req.json().catch(() => null)) as TestBody | null
  const settings = new EmailSettingsService(c.env.DB)
  const to = body?.to?.trim() || user?.email
  if (!to) {
    return c.json({ error: 'no recipient — pass `to` in body or sign in with an email account' }, 400)
  }

  const siteConfig = new SiteConfigService(c.env.DB, { PUBLIC_URL: (c.env as unknown as Record<string, string | undefined>).PUBLIC_URL })
  const { siteName } = await siteConfig.load()

  const { subject, html, text } = renderTestEmail({ siteName })

  try {
    const settingsLoaded = await settings.load()
    const result = await getEmailService().send({
      to,
      subject,
      html,
      text,
      from: settingsLoaded.fromEmail || undefined,
      replyTo: settingsLoaded.replyTo || undefined,
      flow: 'test',
    })

    return c.json({
      success: result.ok,
      result,
    })
  } catch (err) {
    return c.json(
      { error: err instanceof Error ? err.message : String(err) },
      400,
    )
  }
})
