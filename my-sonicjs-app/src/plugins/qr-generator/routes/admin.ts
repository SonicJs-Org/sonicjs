import { Hono } from 'hono'
import { QRService } from '../services/qr.service'
import { renderQRListPage } from '../templates/qr-list.template'
import { renderQRFormPage } from '../templates/qr-form.template'
import { renderQRPreview } from '../templates/qr-preview.template'

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
   * Display the create QR code form with default settings and initial preview
   */
  admin.get('/new', async (c: any) => {
    try {
      const ref = c.req.query('ref') || undefined

      // Get DB and plugin settings for default values
      const db = c.env?.DB || c.get('db')
      const service = new QRService(db)
      const { data: settings } = await service.getSettings()

      // Generate initial preview SVG with defaults
      const initialPreview = service.generate({
        content: 'https://example.com',
        foregroundColor: settings.defaultForegroundColor,
        backgroundColor: settings.defaultBackgroundColor,
        errorCorrection: settings.defaultErrorCorrection,
        size: 200,
        cornerShape: settings.defaultCornerShape || 'square',
        dotShape: settings.defaultDotShape || 'square'
      })

      const html = renderQRFormPage({
        isEdit: false,
        referrerParams: ref,
        user: c.get('user'),
        baseUrl: new URL(c.req.url).origin,
        initialSvg: initialPreview.svg
      })
      return c.html(html)
    } catch (error) {
      console.error('Error loading create form:', error)
      return c.html('<h1>Error loading form</h1>', 500)
    }
  })

  /**
   * GET /admin/qr-codes/:id/edit
   * Display the edit QR code form with current values and preview
   */
  admin.get('/:id/edit', async (c: any) => {
    try {
      const id = c.req.param('id')
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.html('<h1>Database not available</h1>', 500)
      }

      const ref = c.req.query('ref') || undefined
      const service = new QRService(db)
      const qrCode = await service.getById(id)

      if (!qrCode) {
        return c.redirect('/admin/qr-codes', 303)
      }

      // Generate preview SVG for current QR code
      const preview = service.generate({
        content: qrCode.destinationUrl,
        foregroundColor: qrCode.foregroundColor,
        backgroundColor: qrCode.backgroundColor,
        errorCorrection: qrCode.errorCorrection,
        size: 200,
        cornerShape: qrCode.cornerShape,
        dotShape: qrCode.dotShape,
        eyeColor: qrCode.eyeColor,
        logoUrl: qrCode.logoUrl,
        logoAspectRatio: qrCode.logoAspectRatio
      })

      const html = renderQRFormPage({
        isEdit: true,
        qrCode,
        referrerParams: ref,
        user: c.get('user'),
        baseUrl: new URL(c.req.url).origin,
        initialSvg: preview.svg
      })
      return c.html(html)
    } catch (error) {
      console.error('Error loading edit form:', error)
      return c.html('<h1>Error loading form</h1>', 500)
    }
  })

  /**
   * POST /admin/qr-codes/preview
   * Real-time preview endpoint for HTMX - returns preview partial HTML
   */
  admin.post('/preview', async (c: any) => {
    try {
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.html('<p class="text-red-500">Database not available</p>', 500)
      }

      const body = await c.req.parseBody()
      const service = new QRService(db)

      // Parse form values with defaults
      const content = (body.destination_url as string) || 'https://example.com'
      const foregroundColor = (body.foreground_color as string) || '#000000'
      const backgroundColor = (body.background_color as string) || '#ffffff'
      const errorCorrection = (body.error_correction as string) || 'M'
      const cornerShape = (body.corner_shape as string) || 'square'
      const dotShape = (body.dot_shape as string) || 'square'
      const eyeColor = body.eye_color as string || null
      const size = parseInt(body.size as string) || 200

      // Generate preview
      const result = service.generate({
        content,
        foregroundColor,
        backgroundColor,
        errorCorrection: errorCorrection as any,
        size: Math.min(size, 400), // Cap preview size
        cornerShape: cornerShape as any,
        dotShape: dotShape as any,
        eyeColor: eyeColor || null,
        logoUrl: body.logo_url as string || null,
        logoAspectRatio: body.logo_url ? 1 : null // Default to 1:1 if logo present
      })

      // Return just the preview partial for HTMX swap
      const html = renderQRPreview({
        svg: result.svg,
        shortCode: body.short_code as string || undefined,
        baseUrl: new URL(c.req.url).origin,
        qrId: body.id as string || undefined
      })

      return c.html(html)
    } catch (error) {
      console.error('Error generating preview:', error)
      return c.html(`<p class="text-red-500 text-sm">Preview error: ${error instanceof Error ? error.message : 'Unknown error'}</p>`, 500)
    }
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
