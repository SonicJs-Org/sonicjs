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

      // Pre-generate a short code for the preview (will be used on save)
      const { generateUniqueShortCode } = await import('../utils/short-code')
      const provisionalShortCode = await generateUniqueShortCode(db)

      // Generate initial preview SVG with the provisional short URL
      const baseUrl = new URL(c.req.url).origin
      const previewSize = 280 // Fixed preview size for consistent display
      const initialPreview = service.generate({
        content: `${baseUrl}/qr/${provisionalShortCode}`,
        foregroundColor: settings.defaultForegroundColor,
        backgroundColor: settings.defaultBackgroundColor,
        errorCorrection: settings.defaultErrorCorrection,
        size: previewSize,
        cornerShape: settings.defaultCornerShape || 'square',
        dotShape: settings.defaultDotShape || 'square',
        logoUrl: settings.defaultLogoUrl || null,
        logoAspectRatio: settings.defaultLogoUrl ? 1 : null
      })

      const html = renderQRFormPage({
        isEdit: false,
        referrerParams: ref,
        user: c.get('user'),
        baseUrl,
        initialSvg: initialPreview.svg,
        provisionalShortCode,  // Pass to form as hidden field
        defaultSettings: settings  // Pass settings for form defaults
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

      // Generate preview SVG for current QR code at fixed preview size
      // QR code encodes the short URL (for tracking), not the destination URL
      const baseUrl = new URL(c.req.url).origin
      const previewSize = 280 // Fixed preview size for consistent display
      const effectiveEyeColor = (qrCode.eyeColor && qrCode.eyeColor !== qrCode.foregroundColor)
        ? qrCode.eyeColor
        : null

      const preview = service.generate({
        content: `${baseUrl}/qr/${qrCode.shortCode}`,  // Use short URL for tracking
        foregroundColor: qrCode.foregroundColor,
        backgroundColor: qrCode.backgroundColor,
        errorCorrection: qrCode.errorCorrection,
        size: previewSize,
        cornerShape: qrCode.cornerShape,
        dotShape: qrCode.dotShape,
        eyeColor: effectiveEyeColor,
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

      // Get plugin settings for defaults
      const { data: settings } = await service.getSettings()

      // Parse form values with plugin settings as defaults
      const baseUrl = new URL(c.req.url).origin
      const shortCode = body.short_code as string || ''

      // QR code should encode the short URL (for tracking), not the destination URL
      // For new QR codes without a short code yet, show a placeholder
      const content = shortCode
        ? `${baseUrl}/qr/${shortCode}`
        : `${baseUrl}/qr/preview`  // Placeholder for new QR codes

      const foregroundColor = (body.foreground_color as string) || settings.defaultForegroundColor || '#000000'
      const backgroundColor = (body.background_color as string) || settings.defaultBackgroundColor || '#ffffff'
      const errorCorrection = (body.error_correction as string) || settings.defaultErrorCorrection || 'M'
      const cornerShape = (body.corner_shape as string) || settings.defaultCornerShape || 'square'
      const dotShape = (body.dot_shape as string) || settings.defaultDotShape || 'square'
      // Only use eye color if it's different from foreground color
      const rawEyeColor = body.eye_color as string || ''
      const eyeColor = (rawEyeColor && rawEyeColor !== foregroundColor) ? rawEyeColor : null
      console.log('[QR Preview] Eye color check:', { rawEyeColor, foregroundColor, effectiveEyeColor: eyeColor })
      const size = parseInt(body.size as string) || settings.defaultSize || 200
      // Logo URL: use form value if provided, otherwise null
      // Note: empty string means user removed the logo, so don't fall back to default
      const logoUrl = (body.logo_url as string) || null

      // Generate preview at fixed size for consistent display
      const previewSize = 280 // Fixed preview size
      console.log('[QR Preview] Generating with:', { content, shortCode, foregroundColor, backgroundColor, cornerShape, dotShape, previewSize, logoUrl })
      const result = service.generate({
        content,
        foregroundColor,
        backgroundColor,
        errorCorrection: errorCorrection as any,
        size: previewSize, // Always use fixed preview size
        cornerShape: cornerShape as any,
        dotShape: dotShape as any,
        eyeColor: eyeColor || null,
        logoUrl: logoUrl,
        logoAspectRatio: logoUrl ? 1 : null // Default to 1:1 if logo present
      })
      console.log('[QR Preview] Generated SVG length:', result.svg?.length)
      console.log('[QR Preview] SVG first 500 chars:', result.svg?.substring(0, 500))

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
   */
  admin.post('/', async (c: any) => {
    try {
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.html(renderAlertFragment('error', 'Database not available'), 500)
      }

      const body = await c.req.parseBody()
      console.log('[QR Admin] POST / - Form body:', body)

      // Get plugin settings for defaults
      const service = new QRService(db)
      const { data: settings } = await service.getSettings()

      // Only use eye color if it's different from foreground color
      const fgColor = body.foreground_color as string || settings.defaultForegroundColor || '#000000'
      const rawEyeColor = body.eye_color as string || ''
      const effectiveEyeColor = (rawEyeColor && rawEyeColor !== fgColor) ? rawEyeColor : null

      // Use the provisional short code from the form (pre-generated on page load)
      const provisionalShortCode = body.short_code as string || null

      // Logo URL: use form value (which already has the default when form loads)
      // Empty string means user removed the logo
      const logoUrl = (body.logo_url as string) || null

      const input = {
        name: body.name as string || null,
        destinationUrl: body.destination_url as string,
        foregroundColor: fgColor,
        backgroundColor: body.background_color as string || settings.defaultBackgroundColor || '#ffffff',
        errorCorrection: body.error_correction as any || settings.defaultErrorCorrection || 'M',
        size: parseInt(body.size as string) || settings.defaultSize || 300,
        cornerShape: body.corner_shape as any || settings.defaultCornerShape || 'square',
        dotShape: body.dot_shape as any || settings.defaultDotShape || 'square',
        eyeColor: effectiveEyeColor,
        logoUrl: logoUrl,
        logoAspectRatio: logoUrl ? 1 : null,
        shortCode: provisionalShortCode  // Use pre-generated short code
      }

      // Get user ID
      let userId = c.get('user')?.id
      if (!userId) {
        const adminUser = await db.prepare('SELECT id FROM users WHERE role = ? LIMIT 1').bind('admin').first()
        userId = adminUser?.id as string || 'system'
      }

      const result = await service.create(input, userId)

      if (result.success) {
        return c.redirect('/admin/qr-codes?success=' + encodeURIComponent('QR code created successfully'), 303)
      } else {
        let html = ''
        if (result.error) {
          html += renderAlertFragment('error', result.error)
        }
        if (result.warning) {
          html += renderAlertFragment('warning', result.warning)
        }
        return c.html(html || renderAlertFragment('error', 'Failed to create QR code'), 400)
      }
    } catch (error) {
      console.error('[QR Admin] Error creating QR code:', error)
      return c.html(renderAlertFragment('error', `Failed to create QR code: ${error instanceof Error ? error.message : 'Unknown error'}`), 500)
    }
  })

  /**
   * PUT /admin/qr-codes/:id
   * Update an existing QR code
   */
  admin.put('/:id', async (c: any) => {
    try {
      const id = c.req.param('id')
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.html(renderAlertFragment('error', 'Database not available'), 500)
      }

      const body = await c.req.parseBody()
      console.log('[QR Admin] PUT /:id - Form body:', body)

      // Only use eye color if it's different from foreground color
      const fgColor = body.foreground_color as string || '#000000'
      const rawEyeColor = body.eye_color as string || ''
      const effectiveEyeColor = (rawEyeColor && rawEyeColor !== fgColor) ? rawEyeColor : null

      const input = {
        name: body.name as string || null,
        destinationUrl: body.destination_url as string,
        foregroundColor: fgColor,
        backgroundColor: body.background_color as string,
        errorCorrection: body.error_correction as any,
        size: parseInt(body.size as string) || 300,
        cornerShape: body.corner_shape as any || 'square',
        dotShape: body.dot_shape as any || 'square',
        eyeColor: effectiveEyeColor,
        logoUrl: body.logo_url as string || null,
        logoAspectRatio: body.logo_url ? 1 : null
      }

      const userId = c.get('user')?.id
      const service = new QRService(db)
      const result = await service.update(id, input, userId)

      if (result.success) {
        return c.redirect('/admin/qr-codes?success=' + encodeURIComponent('QR code updated successfully'), 303)
      } else {
        let html = ''
        if (result.error) {
          html += renderAlertFragment('error', result.error)
        }
        if (result.warning) {
          html += renderAlertFragment('warning', result.warning)
        }
        return c.html(html || renderAlertFragment('error', 'Failed to update QR code'), 400)
      }
    } catch (error) {
      console.error('[QR Admin] Error updating QR code:', error)
      return c.html(renderAlertFragment('error', `Failed to update QR code: ${error instanceof Error ? error.message : 'Unknown error'}`), 500)
    }
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

  /**
   * GET /admin/qr-codes/:id/preview
   * Returns SVG thumbnail for list view
   */
  admin.get('/:id/preview', async (c: any) => {
    try {
      const id = c.req.param('id')
      const size = parseInt(c.req.query('size') || '40')
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.text('Database not available', 500)
      }

      const service = new QRService(db)
      const qrCode = await service.getById(id)

      if (!qrCode) {
        return c.text('QR code not found', 404)
      }

      // Only use eye color if it's different from foreground color
      const baseUrl = new URL(c.req.url).origin
      const effectiveEyeColor = (qrCode.eyeColor && qrCode.eyeColor !== qrCode.foregroundColor)
        ? qrCode.eyeColor
        : null

      const result = service.generate({
        content: `${baseUrl}/qr/${qrCode.shortCode}`,  // Use short URL for tracking
        foregroundColor: qrCode.foregroundColor,
        backgroundColor: qrCode.backgroundColor,
        errorCorrection: qrCode.errorCorrection,
        size: Math.min(size, 100), // Cap thumbnail size
        cornerShape: qrCode.cornerShape,
        dotShape: qrCode.dotShape,
        eyeColor: effectiveEyeColor,
        logoUrl: qrCode.logoUrl,
        logoAspectRatio: qrCode.logoAspectRatio
      })

      return new Response(result.svg, {
        headers: {
          'Content-Type': 'image/svg+xml',
          'Cache-Control': 'public, max-age=3600'
        }
      })
    } catch (error) {
      console.error('[QR Admin] Error generating preview:', error)
      return c.text('Error generating preview', 500)
    }
  })

  /**
   * GET /admin/qr-codes/:id/download/png
   * Returns PNG file for download with DPI option
   */
  admin.get('/:id/download/png', async (c: any) => {
    try {
      const id = c.req.param('id')
      const dpi = parseInt(c.req.query('dpi') || '300') as 72 | 150 | 300
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.text('Database not available', 500)
      }

      const service = new QRService(db)
      const baseUrl = new URL(c.req.url).origin
      const result = await service.generateForRecordAsPng(id, dpi, false, baseUrl)

      if (!result.success || !result.result) {
        return c.text(result.error || 'Failed to generate PNG', 404)
      }

      const filename = `qr-code-${id.slice(0, 8)}-${dpi}dpi.png`

      return new Response(result.result.buffer, {
        headers: {
          'Content-Type': 'image/png',
          'Content-Disposition': `attachment; filename="${filename}"`,
          'Content-Length': result.result.size.toString()
        }
      })
    } catch (error) {
      console.error('[QR Admin] Error generating PNG:', error)
      return c.text('Error generating PNG', 500)
    }
  })

  return admin
}

export default createQRAdminRoutes
