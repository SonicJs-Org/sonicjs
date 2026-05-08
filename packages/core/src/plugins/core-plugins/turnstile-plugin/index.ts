import { PluginBuilder } from '../../sdk/plugin-builder'
import { TurnstileService } from './services/turnstile'
import { verifyTurnstile } from './middleware/verify'
import manifest from './manifest.json'

/**
 * Cloudflare Turnstile Plugin
 * 
 * Provides CAPTCHA-free bot protection using Cloudflare Turnstile.
 * Can be used with any form by adding the verifyTurnstile middleware.
 * 
 * Settings are managed through the generic admin plugin interface.
 * No custom routes needed - the admin system automatically handles settings.
 * 
 * @example
 * ```typescript
 * import { verifyTurnstile } from '@sonicjs-cms/core/plugins'
 * 
 * app.post('/api/contact', verifyTurnstile, async (c) => {
 *   // Process form after Turnstile verification
 * })
 * ```
 */

// Build the plugin - no custom routes, generic admin handles settings
export const turnstilePlugin = new PluginBuilder({
  // Use manifest.id (not manifest.name) so the plugin's name matches its
  // DB row id — mountPluginManagerRoutes' isPluginEnabled gate looks up
  // `plugins.id`, and a mismatch returns 404 on every request.
  name: manifest.id,
  version: manifest.version,
  description: manifest.description,
  author: { name: manifest.author },
})
  .metadata({
    description: manifest.description,
    author: { name: manifest.author },
  })
  .addService('turnstile', TurnstileService)
  .addSingleMiddleware('verifyTurnstile', verifyTurnstile, {
    description: 'Verify Cloudflare Turnstile token',
    global: false,
  })
  .build()

// Export service and middleware for easy import
export { TurnstileService } from './services/turnstile'
export { verifyTurnstile, createTurnstileMiddleware } from './middleware/verify'
export { renderTurnstileWidget, renderInlineTurnstile, getTurnstileScript, renderExplicitTurnstile } from './components/widget'
export type { TurnstileSettings, TurnstileVerificationResponse } from './services/turnstile'
