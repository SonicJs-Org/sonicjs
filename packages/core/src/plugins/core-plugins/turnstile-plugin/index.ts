/**
 * Cloudflare Turnstile Plugin — Payload-shaped port.
 *
 * CAPTCHA-free bot protection. Settings managed via the generic admin
 * plugin interface (configSchema below); no custom routes needed.
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

import { definePlugin } from '../../sdk/define-plugin'
import { TurnstileService } from './services/turnstile'
import { verifyTurnstile } from './middleware/verify'
import manifest from './manifest.json'

export const turnstilePlugin = definePlugin({
  id: manifest.id,
  version: manifest.version,
  name: manifest.name,
  description: manifest.description,
  sonicjsVersionRange: '^3.0.0',
  author: { name: manifest.author },
})

// Re-exports
export { TurnstileService }
export { verifyTurnstile, createTurnstileMiddleware } from './middleware/verify'
export {
  renderTurnstileWidget,
  renderInlineTurnstile,
  getTurnstileScript,
  renderExplicitTurnstile,
} from './components/widget'
export type { TurnstileSettings, TurnstileVerificationResponse } from './services/turnstile'
