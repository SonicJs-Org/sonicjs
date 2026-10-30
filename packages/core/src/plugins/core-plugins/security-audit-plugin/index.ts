/**
 * Security Audit Plugin — Payload-shaped port.
 */

import { definePlugin } from '../../sdk/define-plugin'
import { securityAuditAdminRoutes } from './routes/admin'
import { securityAuditApiRoutes } from './routes/api'

const SECURITY_ICON = `<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>`

export const securityAuditPlugin = definePlugin({
  id: 'security-audit',
  version: '1.0.0',
  name: 'Security Audit',
  description: 'Security event logging, brute-force detection, and analytics dashboard.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS Team' },

  register(app) {
    app.route('/admin/plugins/security-audit', securityAuditAdminRoutes as any)
    app.route('/api/security-audit', securityAuditApiRoutes as any)
  },

  menu: [
    { label: 'Security', path: '/admin/plugins/security-audit', icon: SECURITY_ICON, order: 85 },
  ],

  activate: async () => console.log('[SecurityAudit] Plugin activated'),
  deactivate: async () => console.log('[SecurityAudit] Plugin deactivated'),
})

export function createSecurityAuditPlugin() {
  return securityAuditPlugin
}

export { SecurityAuditService } from './services/security-audit-service'
export { BruteForceDetector } from './services/brute-force-detector'
export { securityAuditMiddleware } from './middleware/audit-middleware'
export { securityAuditAdminRoutes } from './routes/admin'
export { securityAuditApiRoutes } from './routes/api'
export default securityAuditPlugin
