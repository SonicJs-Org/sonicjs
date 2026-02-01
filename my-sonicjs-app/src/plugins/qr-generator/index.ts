import { PluginBuilder } from '@sonicjs-cms/core'
import type { Plugin, PluginContext } from '@sonicjs-cms/core'
import manifest from './manifest.json'

// Service will be imported in Plan 02 after creation
// import { QRService } from './services/qr.service'

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

  // NOTE: Routes will be added in Phase 4 (Admin Interface)
  // NOTE: Menu items will be added in Phase 4 (Admin Interface)

  // Service registration placeholder - uncomment in Plan 02
  // let qrService: QRService | null = null
  //
  // builder.addService('qrService', {
  //   implementation: QRService,
  //   description: 'QR code generation and management service',
  //   singleton: true
  // })

  // Lifecycle hooks - will be implemented in Plan 02
  builder.lifecycle({
    install: async (context: PluginContext) => {
      console.log('[QRGenerator] Plugin install started')
      // TODO: Run migration in Plan 02
      console.log('[QRGenerator] Plugin installed successfully')
    },
    activate: async (context: PluginContext) => {
      console.log('[QRGenerator] Plugin activated')
    },
    deactivate: async (context: PluginContext) => {
      console.log('[QRGenerator] Plugin deactivated')
    },
    uninstall: async (context: PluginContext) => {
      console.log('[QRGenerator] Plugin uninstalled')
    },
    configure: async (config: any) => {
      console.log('[QRGenerator] Plugin configured', config)
    }
  })

  return builder.build()
}

export default createQRGeneratorPlugin()
