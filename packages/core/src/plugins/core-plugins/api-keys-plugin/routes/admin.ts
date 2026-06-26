import { Hono } from 'hono'
import { z } from 'zod'
import { requireAuth } from '../../../../middleware'
import { PluginService } from '../../../../services'
import { ApiKeyService } from '../services/api-key-service'
import { renderApiKeysPage } from '../components/keys-page'
import { DEFAULT_SETTINGS, type ApiKeysSettings } from '../types'
import type { Bindings, Variables } from '../../../../app'

const adminRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

const DAY_MS = 24 * 60 * 60 * 1000

const createSchema = z.object({
  name: z.string().min(1).max(100),
  // Optional lifetime in days; omitted/null → plugin default (which may be "never").
  expiresInDays: z.number().int().positive().max(3650).nullish(),
})

async function getSettings(db: any): Promise<ApiKeysSettings> {
  try {
    const plugin = await new PluginService(db).getPlugin('api-keys')
    if (plugin?.settings) {
      const s = typeof plugin.settings === 'string' ? JSON.parse(plugin.settings) : plugin.settings
      return { ...DEFAULT_SETTINGS, ...s }
    }
  } catch {
    /* fall through to defaults */
  }
  return DEFAULT_SETTINGS
}

// Admin-only: only portal admins reach /admin/*, but guard explicitly so the
// management API can never be hit by a lower role that slips past route mounting.
adminRoutes.use('*', requireAuth())
adminRoutes.use('*', async (c, next) => {
  const user = c.get('user')
  if (user?.role !== 'admin') {
    return c.json({ error: 'Access denied' }, 403)
  }
  return next()
})

// ── Admin UI page ───────────────────────────────────────────────────────────
adminRoutes.get('/', async (c) => {
  const user = c.get('user')!
  const tenantId = (c.get('tenantId') as string) || 'default'
  const keys = await new ApiKeyService(c.env.DB, tenantId).list(user.userId)
  return c.html(
    renderApiKeysPage({
      keys,
      user: { name: user.email, email: user.email, role: user.role },
      version: c.get('appVersion'),
      dynamicMenuItems: c.get('pluginMenuItems'),
    }),
  )
})

// ── JSON management API (scoped to the current admin's own keys) ─────────────
adminRoutes.get('/api/keys', async (c) => {
  const user = c.get('user')!
  const tenantId = (c.get('tenantId') as string) || 'default'
  const keys = await new ApiKeyService(c.env.DB, tenantId).list(user.userId)
  return c.json({ keys })
})

adminRoutes.post('/api/keys', async (c) => {
  const user = c.get('user')!
  const tenantId = (c.get('tenantId') as string) || 'default'
  const body = await c.req.json().catch(() => ({}))
  const parsed = createSchema.safeParse(body)
  if (!parsed.success) {
    return c.json({ error: 'Invalid request', details: parsed.error.flatten() }, 400)
  }

  const settings = await getSettings(c.env.DB)
  const svc = new ApiKeyService(c.env.DB, tenantId)

  // Enforce the per-user cap.
  if ((await svc.countForUser(user.userId)) >= settings.maxKeysPerUser) {
    return c.json({ error: `API key limit reached (max ${settings.maxKeysPerUser})` }, 409)
  }

  // Explicit lifetime wins; else fall back to the plugin default (0 = never).
  const days = parsed.data.expiresInDays ?? (settings.defaultExpiryDays > 0 ? settings.defaultExpiryDays : null)
  const expiresAt = days ? Date.now() + days * DAY_MS : null

  const created = await svc.create({ userId: user.userId, name: parsed.data.name, expiresAt })
  // `key` is shown once here; clients must store it now.
  return c.json({ apiKey: created }, 201)
})

adminRoutes.delete('/api/keys/:id', async (c) => {
  const user = c.get('user')!
  const tenantId = (c.get('tenantId') as string) || 'default'
  const ok = await new ApiKeyService(c.env.DB, tenantId).revoke(c.req.param('id') ?? '', user.userId)
  if (!ok) return c.json({ error: 'API key not found' }, 404)
  return c.json({ success: true })
})

export { adminRoutes as apiKeysAdminRoutes }
