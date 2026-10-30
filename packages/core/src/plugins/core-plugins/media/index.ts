/**
 * Core Media Plugin
 * 
 * Provides media management and processing extensions
 */

import { Hono } from 'hono'
import { definePlugin } from '../../sdk/define-plugin'

function buildMediaApi(): Hono {
  // Create media API routes
  const mediaAPI = new Hono()

  // GET /media - List media files
  mediaAPI.get('/', async (c) => {
    const page = parseInt(c.req.query('page') || '1')
    const limit = parseInt(c.req.query('limit') || '20')
    const _type = c.req.query('type') // image, video, document, etc.

    return c.json({
      message: 'Media list',
      data: {
        files: [],
        pagination: { page, limit, total: 0 }
      }
    })
  })

  // POST /media/upload - Upload media file
  mediaAPI.post('/upload', async (c) => {
    // File upload logic would integrate with existing media service
    return c.json({
      message: 'File uploaded successfully',
      data: {
        id: 'media-123',
        filename: 'example.jpg',
        url: '/media/example.jpg',
        size: 1024,
        type: 'image/jpeg'
      }
    })
  })

  // GET /media/:id - Get media file info
  mediaAPI.get('/:id', async (c) => {
    const id = c.req.param('id')
    return c.json({
      message: 'Media file info',
      data: {
        id,
        filename: 'example.jpg',
        url: `/media/${id}`,
        metadata: {
          width: 1920,
          height: 1080,
          format: 'JPEG'
        }
      }
    })
  })

  // DELETE /media/:id - Delete media file
  mediaAPI.delete('/:id', async (c) => {
    const id = c.req.param('id')
    return c.json({
      message: 'Media file deleted',
      data: { id }
    })
  })

  // POST /media/process - Process media (resize, compress, etc.)
  mediaAPI.post('/process', async (c) => {
    const { id, operations } = await c.req.json()

    return c.json({
      message: 'Media processing started',
      data: {
        jobId: `job-${Date.now()}`,
        status: 'processing'
      }
    })
  })

  // POST /media/create-folder - Create a new folder
  mediaAPI.post('/create-folder', async (c) => {
    try {
      const { folderName } = await c.req.json()

      if (!folderName || typeof folderName !== 'string') {
        return c.json({ success: false, error: 'Folder name is required' }, 400)
      }

      // Validate folder name format
      const folderPattern = /^[a-z0-9-_]+$/
      if (!folderPattern.test(folderName)) {
        return c.json({
          success: false,
          error: 'Folder name can only contain lowercase letters, numbers, hyphens, and underscores'
        }, 400)
      }

      // Note: In a real implementation, you would check if the folder already exists
      // and create it in R2 or update the database accordingly
      // For now, we'll return success as folders are tracked in the media files table

      return c.json({
        success: true,
        message: `Folder "${folderName}" created successfully`,
        data: { folderName }
      })
    } catch (error) {
      console.error('Create folder error:', error)
      return c.json({ success: false, error: 'Failed to create folder' }, 500)
    }
  })

  // POST /media/bulk-move - Move multiple files to a folder
  mediaAPI.post('/bulk-move', async (c) => {
    try {
      const { fileIds, folder } = await c.req.json()

      if (!Array.isArray(fileIds) || fileIds.length === 0) {
        return c.json({ success: false, error: 'File IDs array is required' }, 400)
      }

      if (!folder || typeof folder !== 'string') {
        return c.json({ success: false, error: 'Target folder is required' }, 400)
      }

      // Note: In a real implementation, you would update the database
      // to move the files to the specified folder
      // For now, we'll return a success response

      return c.json({
        success: true,
        message: `Successfully moved ${fileIds.length} file(s) to ${folder}`,
        summary: {
          successful: fileIds.length,
          failed: 0,
          total: fileIds.length
        }
      })
    } catch (error) {
      console.error('Bulk move error:', error)
      return c.json({ success: false, error: 'Failed to move files' }, 500)
    }
  })

  return mediaAPI
}

export const mediaPlugin = definePlugin({
  id: 'core-media',
  version: '1.0.0',
  name: 'Media',
  description: 'Core media management and processing plugin.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS Team', email: 'team@sonicjs.com' },
  dependencies: ['core-auth'],
  capabilities: ['hooks.content:subscribe'],

  register(app) {
    app.route('/api/media', buildMediaApi())
  },

  menu: [
    { label: 'Media', path: '/admin/media', icon: 'photo', order: 30, permissions: ['admin', 'media:manage'] },
  ],

  async onBoot(ctx) {
    // Legacy non-typed media hooks — subscribe via the raw bus.
    const hooks = (ctx.raw as any)?.hooks
    if (!hooks?.register) return
    hooks.register('media:upload', async (data: any) => {
      console.info(`Media upload event: ${data.filename}`)
      if (data.mimeType?.startsWith('image/')) data.generateThumbnail = true
      return data
    }, 10)
    hooks.register('media:delete', async (data: any) => {
      console.info(`Media delete event: ${data.id}`)
      data.cleanupFiles = true
      return data
    }, 10)
    hooks.register('content:save', async (data: any) => {
      const content = data.content || ''
      const mediaReferences = content.match(/\/media\/[a-zA-Z0-9-]+/g) || []
      if (mediaReferences.length > 0) {
        data.mediaReferences = mediaReferences
      }
      return data
    }, 8)
  },

  install: async () => console.info('Installing media plugin...'),
  activate: async () => console.info('Activating media plugin...'),
  deactivate: async () => console.info('Deactivating media plugin...'),
})

export function createMediaPlugin() {
  return mediaPlugin
}
