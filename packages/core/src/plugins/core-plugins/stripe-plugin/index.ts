/**
 * Stripe Plugin — Payload-shaped port.
 */

import { definePlugin } from '../../sdk/define-plugin'
import { stripeAdminRoutes } from './routes/admin'
import { stripeApiRoutes } from './routes/api'

const STRIPE_ICON = `<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z"/></svg>`

export const stripePlugin = definePlugin({
  id: 'stripe',
  version: '1.0.0',
  name: 'Stripe',
  description: 'Stripe subscription management with webhook handling, checkout sessions, and subscription gating.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS Team' },

  register(app) {
    app.route('/admin/plugins/stripe', stripeAdminRoutes as any)
    app.route('/api/stripe', stripeApiRoutes as any)
  },

  menu: [
    { label: 'Stripe', path: '/admin/plugins/stripe', icon: STRIPE_ICON, order: 75 },
  ],

  install: async () => console.log('[Stripe] Plugin installed'),
  activate: async () => console.log('[Stripe] Plugin activated'),
  deactivate: async () => console.log('[Stripe] Plugin deactivated'),
  uninstall: async () => console.log('[Stripe] Plugin uninstalled'),
})

export function createStripePlugin() {
  return stripePlugin
}

export { SubscriptionService } from './services/subscription-service'
export { StripeAPI } from './services/stripe-api'
export { requireSubscription } from './middleware/require-subscription'
export default stripePlugin
