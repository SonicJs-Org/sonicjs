import { Hono } from 'hono'
import { QRService } from '../services/qr.service'
import { renderQRListPage } from '../templates/qr-list.template'

/**
 * Render an alert message HTML fragment for HTMX
 */
function renderAlertFragment(type: 'error' | 'warning' | 'success', message: string): string {
  const colors = {
    error: 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20 text-red-800 dark:text-red-400',
    warning: 'border-yellow-200 dark:border-yellow-800 bg-yellow-50 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-400',
    success: 'border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-900/20 text-green-800 dark:text-green-400'
  }
  return `<div class="rounded-lg border ${colors[type]} p-4 mb-4"><p class="text-sm">${message}</p></div>`
}

/**
 * Create admin route handlers for QR code management UI
 */
export function createQRAdminRoutes(): Hono {
  const admin = new Hono()

  /**
   * GET / (mounted at /admin/qr-codes)
   * Display the QR codes list page with search and pagination
   */
  admin.get('/', async (c: any) => {
    try {
      // Get DB from context (Cloudflare Workers env)
      const db = c.env?.DB || c.get('db')
      if (!db) {
        console.error('[QR Admin] Database not available. c.env:', c.env, 'c.get(db):', c.get('db'))
        return c.html('<h1>Database not available</h1>', 500)
      }

      // Parse query parameters
      const page = parseInt(c.req.query('page') || '1')
      const limit = parseInt(c.req.query('limit') || '20')
      const search = c.req.query('search') || undefined
      const successMessage = c.req.query('success') || undefined

      // Fetch QR codes and count in parallel
      const service = new QRService(db)
      const [qrCodes, total] = await Promise.all([
        service.list({ limit, offset: (page - 1) * limit, search }),
        service.count({ search })
      ])

      // Calculate pagination
      const totalPages = Math.ceil(total / limit)

      // Render page
      const html = renderQRListPage({
        qrCodes,
        pagination: {
          page,
          limit,
          total,
          totalPages
        },
        filters: {
          search
        },
        user: c.get('user'),
        successMessage
      })

      return c.html(html)
    } catch (error) {
      console.error('Error loading QR codes list page:', error)
      return c.html('<h1>Error loading QR codes</h1>', 500)
    }
  })

  /**
   * GET /admin/qr-codes/new
   * Display the create QR code form
   * (Placeholder - will be implemented in Plan 03)
   */
  admin.get('/new', async (c: any) => {
    return c.html('<h1>Create QR Code - Coming Soon</h1><p><a href="/admin/qr-codes">Back to list</a></p>')
  })

  /**
   * GET /admin/qr-codes/:id/edit
   * Display the edit QR code form
   * (Placeholder - will be implemented in Plan 03)
   */
  admin.get('/:id/edit', async (c: any) => {
    const id = c.req.param('id')
    return c.html(`<h1>Edit QR Code ${id} - Coming Soon</h1><p><a href="/admin/qr-codes">Back to list</a></p>`)
  })

  /**
   * POST /admin/qr-codes
   * Create a new QR code
   * (Placeholder - will be implemented in Plan 03)
   */
  admin.post('/', async (c: any) => {
    return c.html(renderAlertFragment('error', 'Create not yet implemented'), 501)
  })

  /**
   * PUT /admin/qr-codes/:id
   * Update an existing QR code
   * (Placeholder - will be implemented in Plan 03)
   */
  admin.put('/:id', async (c: any) => {
    return c.html(renderAlertFragment('error', 'Update not yet implemented'), 501)
  })

  /**
   * DELETE /admin/qr-codes/:id
   * Delete a QR code
   */
  admin.delete('/:id', async (c: any) => {
    try {
      const id = c.req.param('id')
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.json({ success: false, error: 'Database not available' }, 500)
      }

      const service = new QRService(db)
      const result = await service.delete(id)

      if (result.success) {
        return c.json({ success: true, message: 'QR code deleted successfully' })
      } else {
        return c.json({ success: false, error: result.error }, 404)
      }
    } catch (error) {
      console.error('Error deleting QR code:', error)
      return c.json({ success: false, error: 'Failed to delete QR code' }, 500)
    }
  })

  return admin
}

export default createQRAdminRoutes
