import { PluginBuilder } from '@sonicjs-cms/core'
import type { Plugin, PluginContext } from '@sonicjs-cms/core'
import manifest from './manifest.json'
import { QRService } from './services/qr.service'
import qrRedirectRoutes from './routes/qr-redirect'
import { createQRAdminRoutes } from './routes/admin'

// Export types for external use
export type { QRCode, CreateQRCodeInput, UpdateQRCodeInput, QRCodeGenerateOptions, QRCodeGenerateResult } from './types'
export { QRService } from './services/qr.service'
export { createQRRedirectHandler } from './routes/qr-redirect'
export { createQRAdminRoutes } from './routes/admin'

export function createQRGeneratorPlugin(): Plugin {
  const builder = PluginBuilder.create({
    name: manifest.id,
    version: manifest.version,
    description: manifest.description
  })

  builder.metadata({
    author: { name: manifest.author },
    license: manifest.license,
    compatibility: '^2.0.0'
  })

  // Public route: QR code redirect handler
  // Handles /qr/:code requests with 302 redirect or 410 expired page
  builder.addRoute('/', qrRedirectRoutes, {
    description: 'QR code redirect routes',
    requiresAuth: false,
    priority: 10  // High priority to ensure /qr/:code is matched before catch-all routes
  })

  // Admin routes for QR code management UI
  builder.addRoute('/admin/qr-codes', createQRAdminRoutes(), {
    description: 'QR code management admin routes',
    requiresAuth: true,
    priority: 100
  })

  // Add menu item in admin sidebar
  builder.addMenuItem('QR Codes', '/admin/qr-codes', {
    icon: 'qr-code',
    order: 86,
    permissions: ['admin', 'qr.manage']
  })

  // Register service
  let qrService: QRService | null = null

  builder.addService('qrService', {
    implementation: QRService,
    description: 'QR code generation and management service',
    singleton: true
  })

  // Lifecycle hooks
  builder.lifecycle({
    install: async (context: PluginContext) => {
      console.log('[QRGenerator] Plugin install started')
      qrService = new QRService(context.db)
      await qrService.install()
      console.log('[QRGenerator] Plugin installed successfully')
    },
    activate: async (context: PluginContext) => {
      console.log('[QRGenerator] Plugin activate started')
      qrService = new QRService(context.db)
      await qrService.activate()
      console.log('[QRGenerator] Plugin activated')
    },
    deactivate: async (context: PluginContext) => {
      console.log('[QRGenerator] Plugin deactivate started')
      if (qrService) {
        await qrService.deactivate()
        qrService = null
      }
      console.log('[QRGenerator] Plugin deactivated')
    },
    uninstall: async (context: PluginContext) => {
      console.log('[QRGenerator] Plugin uninstall started')
      if (qrService) {
        await qrService.uninstall()
        qrService = null
      }
      console.log('[QRGenerator] Plugin uninstalled')
    },
    configure: async (config: any) => {
      console.log('[QRGenerator] Plugin configure started', config)
      if (qrService) {
        await qrService.saveSettings(config)
      }
      console.log('[QRGenerator] Plugin configured')
    }
  })

  return builder.build()
}

export default createQRGeneratorPlugin()
