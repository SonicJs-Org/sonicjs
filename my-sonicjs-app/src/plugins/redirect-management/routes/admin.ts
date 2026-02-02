import { Hono } from 'hono'
import { RedirectService } from '../services/redirect'
import { renderRedirectListPage } from '../templates/redirect-list.template'
import { renderRedirectFormPage } from '../templates/redirect-form.template'
import { generateCSV, buildExportFilename, parseCSV, validateCSVBatch, generateErrorCSV } from '../services/csv.service'
import type { RedirectFilter, MatchType, StatusCode, CreateRedirectInput, UpdateRedirectInput, DuplicateHandling, ParsedRedirectRow } from '../types'

/**
 * Render an alert message HTML fragment for HTMX
 */
function renderAlertFragment(type: 'error' | 'warning', message: string): string {
  const colors = {
    error: 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20 text-red-800 dark:text-red-400',
    warning: 'border-yellow-200 dark:border-yellow-800 bg-yellow-50 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-400'
  }
  return `<div class="rounded-lg border ${colors[type]} p-4 mb-4"><p class="text-sm">${message}</p></div>`
}

/**
 * Create admin route handlers for redirect management UI
 */
export function createRedirectAdminRoutes(): Hono {
  const admin = new Hono()

  /**
   * GET / (mounted at /admin/redirects)
   * Display the redirect list page with filtering and pagination
   */
  admin.get('/', async (c: any) => {
    try {
      // Get DB from context (Cloudflare Workers env)
      const db = c.env?.DB || c.get('db')
      if (!db) {
        console.error('[Redirect Admin] Database not available. c.env:', c.env, 'c.get(db):', c.get('db'))
        return c.html('<h1>Database not available</h1>', 500)
      }

      // Parse query parameters
      const page = parseInt(c.req.query('page') || '1')
      const limit = parseInt(c.req.query('limit') || '20')
      const search = c.req.query('search') || undefined
      const statusCodeParam = c.req.query('statusCode')
      const matchTypeParam = c.req.query('matchType')
      const isActiveParam = c.req.query('isActive')
      const successMessage = c.req.query('success') || undefined

      // Parse status code filter
      let statusCode: StatusCode | undefined
      if (statusCodeParam && ['301', '302', '307', '308', '410'].includes(statusCodeParam)) {
        statusCode = parseInt(statusCodeParam) as StatusCode
      }

      // Parse match type filter
      let matchType: MatchType | undefined
      if (matchTypeParam && ['0', '1', '2'].includes(matchTypeParam)) {
        matchType = parseInt(matchTypeParam) as MatchType
      }

      // Parse active status filter
      let isActive: boolean | undefined
      if (isActiveParam === 'true') {
        isActive = true
      } else if (isActiveParam === 'false') {
        isActive = false
      }

      // Build filter object with only defined properties
      const filter: RedirectFilter = {
        limit,
        offset: (page - 1) * limit
      }

      if (search !== undefined) filter.search = search
      if (statusCode !== undefined) filter.statusCode = statusCode
      if (matchType !== undefined) filter.matchType = matchType
      if (isActive !== undefined) filter.isActive = isActive

      // Fetch redirects and count in parallel
      const service = new RedirectService(db)
      const [redirects, total] = await Promise.all([
        service.list(filter),
        service.count(filter)
      ])

      // Calculate pagination
      const totalPages = Math.ceil(total / limit)

      // Render page
      const html = renderRedirectListPage({
        redirects,
        pagination: {
          page,
          limit,
          total,
          totalPages
        },
        filters: {
          search,
          statusCode: statusCodeParam,
          matchType: matchTypeParam,
          isActive: isActiveParam
        },
        user: c.get('user'),
        successMessage
      })

      return c.html(html)
    } catch (error) {
      console.error('Error loading redirect list page:', error)
      return c.html('<h1>Error loading redirects</h1>', 500)
    }
  })

  /**
   * GET /admin/redirects/export
   * Export redirects as CSV file, respecting current filters
   */
  admin.get('/export', async (c: any) => {
    try {
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.text('Database not available', 500)
      }

      // Parse the same filter parameters as the list route
      const statusCodeParam = c.req.query('statusCode')
      const matchTypeParam = c.req.query('matchType')
      const isActiveParam = c.req.query('isActive')
      const search = c.req.query('search') || undefined

      // Build filter object (same logic as list route)
      const filter: RedirectFilter = {}

      if (statusCodeParam && ['301', '302', '307', '308', '410'].includes(statusCodeParam)) {
        filter.statusCode = parseInt(statusCodeParam) as StatusCode
      }
      if (matchTypeParam && ['0', '1', '2'].includes(matchTypeParam)) {
        filter.matchType = parseInt(matchTypeParam) as MatchType
      }
      if (isActiveParam === 'true') {
        filter.isActive = true
      } else if (isActiveParam === 'false') {
        filter.isActive = false
      }
      if (search) {
        filter.search = search
      }

      // Remove pagination limits - export all matching redirects
      // (but keep a reasonable safety limit)
      filter.limit = 10000
      filter.offset = 0

      // Fetch redirects matching filters
      const service = new RedirectService(db)
      const redirects = await service.list(filter)

      // Generate CSV
      const csv = generateCSV(redirects)

      // Build descriptive filename
      const filename = buildExportFilename({
        statusCode: statusCodeParam,
        matchType: matchTypeParam,
        isActive: isActiveParam,
        search
      })

      // Return CSV with proper headers for download
      return new Response(csv, {
        status: 200,
        headers: {
          'Content-Type': 'text/csv; charset=utf-8',
          'Content-Disposition': `attachment; filename="${filename}"`
        }
      })
    } catch (error) {
      console.error('Error exporting CSV:', error)
      return c.text('Failed to export redirects', 500)
    }
  })

  /**
   * POST /admin/redirects/import
   * Import redirects from CSV file
   */
  admin.post('/import', async (c: any) => {
    try {
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.html(renderAlertFragment('error', 'Database not available'), 500)
      }

      // Parse multipart form data
      const body = await c.req.parseBody()
      const file = body.csv_file as File
      const duplicateHandling = (body.duplicate_handling || 'reject') as DuplicateHandling

      // Validate file exists
      if (!file || file.size === 0) {
        return c.html(renderAlertFragment('error', 'No file uploaded'), 400)
      }

      // Validate file size (10MB limit)
      const MAX_FILE_SIZE = 10 * 1024 * 1024
      if (file.size > MAX_FILE_SIZE) {
        return c.html(
          renderAlertFragment('error',
            `File too large. Maximum size is 10MB, got ${(file.size / 1024 / 1024).toFixed(1)}MB`
          ),
          400
        )
      }

      // Parse CSV content
      const content = await file.text()
      const parseResult = parseCSV(content)

      if (!parseResult.isValid) {
        // Parse errors (malformed CSV)
        const errorList = parseResult.errors.map(e => `Line ${e.line}: ${e.error}`).join('; ')
        return c.html(
          renderAlertFragment('error', `CSV parsing failed: ${errorList}`),
          400
        )
      }

      // Validate row count (10,000 limit)
      const MAX_ROWS = 10000
      if (parseResult.rows.length > MAX_ROWS) {
        return c.html(
          renderAlertFragment('error',
            `Too many rows. Maximum is ${MAX_ROWS}, got ${parseResult.rows.length}`
          ),
          400
        )
      }

      if (parseResult.rows.length === 0) {
        return c.html(
          renderAlertFragment('error', 'CSV file is empty (no data rows found)'),
          400
        )
      }

      // Get existing redirects for validation
      const service = new RedirectService(db)
      const existingMap = await service.getAllSourceDestinationMap()

      // Validate all rows
      const validation = await validateCSVBatch(
        parseResult.rows as ParsedRedirectRow[],
        existingMap,
        duplicateHandling
      )

      if (!validation.isValid) {
        // Return error CSV as download
        const errorCSV = generateErrorCSV(parseResult.rows as ParsedRedirectRow[], validation.errors)

        return new Response(errorCSV, {
          status: 400,
          headers: {
            'Content-Type': 'text/csv; charset=utf-8',
            'Content-Disposition': 'attachment; filename="import-errors.csv"'
          }
        })
      }

      // All valid - batch insert
      const userId = c.get('user')?.id
      let actualUserId = userId
      if (!actualUserId) {
        const adminUser = await db.prepare('SELECT id FROM users WHERE role = ? LIMIT 1').bind('admin').first()
        actualUserId = adminUser?.id as string || 'system'
      }

      const imported = await service.batchCreate(validation.validRows, actualUserId)

      // Build success message
      let message = `Successfully imported ${imported} redirect${imported !== 1 ? 's' : ''}`
      if (validation.skipped > 0) {
        message += ` (${validation.skipped} duplicate${validation.skipped !== 1 ? 's' : ''} skipped)`
      }

      // Return success with HX-Redirect header for HTMX compatibility
      return new Response(null, {
        status: 200,
        headers: {
          'HX-Redirect': `/admin/redirects?success=${encodeURIComponent(message)}`
        }
      })

    } catch (error) {
      console.error('Error importing CSV:', error)
      return c.html(
        renderAlertFragment('error',
          `Failed to import CSV: ${error instanceof Error ? error.message : 'Unknown error'}`
        ),
        500
      )
    }
  })

  /**
   * GET /admin/redirects/new
   * Display the create redirect form
   */
  admin.get('/new', async (c: any) => {
    try {
      const ref = c.req.query('ref') || undefined
      const html = renderRedirectFormPage({
        isEdit: false,
        referrerParams: ref,
        user: c.get('user')
      })
      return c.html(html)
    } catch (error) {
      console.error('Error loading create form:', error)
      return c.html('<h1>Error loading form</h1>', 500)
    }
  })

  /**
   * GET /admin/redirects/:id/edit
   * Display the edit redirect form
   */
  admin.get('/:id/edit', async (c: any) => {
    try {
      const id = c.req.param('id')
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.html('<h1>Database not available</h1>', 500)
      }

      const ref = c.req.query('ref') || undefined
      const service = new RedirectService(db)
      const redirect = await service.getById(id)

      if (!redirect) {
        return c.redirect('/admin/redirects', 303)
      }

      const html = renderRedirectFormPage({
        isEdit: true,
        redirect,
        referrerParams: ref,
        user: c.get('user')
      })
      return c.html(html)
    } catch (error) {
      console.error('Error loading edit form:', error)
      return c.html('<h1>Error loading form</h1>', 500)
    }
  })

  /**
   * POST /admin/redirects
   * Create a new redirect
   */
  admin.post('/', async (c: any) => {
    console.error('=== POST /admin/redirects HANDLER HIT ===')
    console.error('[Redirect Admin] Request URL:', c.req.url)
    console.error('[Redirect Admin] Request method:', c.req.method)
    console.error('[Redirect Admin] Request headers:', Object.fromEntries(c.req.raw.headers.entries()))

    try {
      const db = c.env?.DB || c.get('db')
      console.error('[Redirect Admin] Database available:', !!db)
      if (!db) {
        console.error('[Redirect Admin] NO DATABASE - returning 500')
        return c.html('<h1>Database not available</h1>', 500)
      }

      console.error('[Redirect Admin] About to parse body...')
      const body = await c.req.parseBody()
      console.error('[Redirect Admin] POST /admin/redirects - Form body:', body)

      const input: CreateRedirectInput = {
        source: body.source as string,
        destination: body.destination as string,
        statusCode: (parseInt(body.status_code as string) || 301) as StatusCode,
        matchType: (parseInt(body.match_type as string) || 0) as MatchType,
        preserveQueryString: body.preserve_query_string === '1',
        includeSubdomains: body.include_subdomains === '1',
        subpathMatching: body.subpath_matching === '1',
        preservePathSuffix: body.preserve_path_suffix === '1',
        isActive: body.active === '1'
      }

      console.log('[Redirect Admin] Parsed input:', JSON.stringify(input, null, 2))

      // Get user ID from context or fallback to first admin user
      let userId = c.get('user')?.id
      if (!userId) {
        // Fallback: get first admin user from database
        const adminUser = await db.prepare('SELECT id FROM users WHERE role = ? LIMIT 1').bind('admin').first()
        userId = adminUser?.id as string || 'system'
      }

      const service = new RedirectService(db, c.env)
      const result = await service.create(input, userId)

      console.log('[Redirect Admin] Service result:', JSON.stringify({ success: result.success, error: result.error, warning: result.warning }, null, 2))

      if (result.success) {
        // Use HTTP 303 See Other - forces browser to use GET when following redirect
        return c.redirect('/admin/redirects', 303)
      } else {
        // Return error/warning fragments for HTMX to insert into #form-messages
        let html = ''
        if (result.error) {
          console.log('[Redirect Admin] Returning 400 with error:', result.error)
          html += renderAlertFragment('error', result.error)
        }
        if (result.warning) {
          html += renderAlertFragment('warning', result.warning)
        }
        return c.html(html || renderAlertFragment('error', 'An error occurred'), 400)
      }
    } catch (error) {
      console.error('[Redirect Admin] Error creating redirect:', error)
      // Return error fragment for HTMX to insert into #form-messages
      const errorMessage = error instanceof Error ? error.message : String(error)
      return c.html(renderAlertFragment('error', `Failed to create redirect: ${errorMessage}`), 500)
    }
  })

  /**
   * PUT /admin/redirects/:id
   * Update an existing redirect
   */
  admin.put('/:id', async (c: any) => {
    try {
      const id = c.req.param('id')
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.html('<h1>Database not available</h1>', 500)
      }

      const body = await c.req.parseBody()
      console.log('[Redirect Admin] PUT /admin/redirects/:id - Form body:', body)

      const input: UpdateRedirectInput = {
        source: body.source as string,
        destination: body.destination as string,
        statusCode: (parseInt(body.status_code as string) || 301) as StatusCode,
        matchType: (parseInt(body.match_type as string) || 0) as MatchType,
        preserveQueryString: body.preserve_query_string === '1',
        includeSubdomains: body.include_subdomains === '1',
        subpathMatching: body.subpath_matching === '1',
        preservePathSuffix: body.preserve_path_suffix === '1',
        isActive: body.active === '1'
      }

      console.log('[Redirect Admin] Parsed input:', JSON.stringify(input, null, 2))

      // Get user ID from context
      const userId = c.get('user')?.id
      const service = new RedirectService(db, c.env)
      const result = await service.update(id, input, userId)

      console.log('[Redirect Admin] Service result:', JSON.stringify({ success: result.success, error: result.error, warning: result.warning }, null, 2))

      if (result.success) {
        // Use HTTP 303 See Other - forces browser to use GET when following redirect
        return c.redirect('/admin/redirects', 303)
      } else {
        // Return error/warning fragments for HTMX to insert into #form-messages
        let html = ''
        if (result.error) {
          console.log('[Redirect Admin] Returning 400 with error:', result.error)
          html += renderAlertFragment('error', result.error)
        }
        if (result.warning) {
          html += renderAlertFragment('warning', result.warning)
        }
        return c.html(html || renderAlertFragment('error', 'An error occurred'), 400)
      }
    } catch (error) {
      console.error('[Redirect Admin] Error updating redirect:', error)
      const errorMessage = error instanceof Error ? error.message : String(error)
      return c.html(renderAlertFragment('error', `Failed to update redirect: ${errorMessage}`), 500)
    }
  })

  /**
   * DELETE /admin/redirects/:id
   * Delete a single redirect
   */
  admin.delete('/:id', async (c: any) => {
    try {
      const id = c.req.param('id')
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.json({ success: false, error: 'Database not available' }, 500)
      }

      const service = new RedirectService(db, c.env)
      const result = await service.delete(id)

      if (result.success) {
        return c.json({ success: true, message: 'Redirect deleted successfully' })
      } else {
        return c.json({ success: false, error: result.error }, 404)
      }
    } catch (error) {
      console.error('Error deleting redirect:', error)
      return c.json({ success: false, error: 'Failed to delete redirect' }, 500)
    }
  })

  /**
   * POST /admin/redirects/bulk-delete
   * Delete multiple redirects in bulk
   */
  admin.post('/bulk-delete', async (c: any) => {
    try {
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.json({ success: false, error: 'Database not available' }, 500)
      }

      // Parse request body to get IDs
      const body = await c.req.json()
      const ids: string[] = body.ids || []

      if (!Array.isArray(ids) || ids.length === 0) {
        return c.json({ success: false, error: 'No redirect IDs provided' }, 400)
      }

      const service = new RedirectService(db)
      let deleted = 0
      let failed = 0
      const errors: string[] = []

      // Delete each redirect
      for (const id of ids) {
        try {
          const result = await service.delete(id)
          if (result.success) {
            deleted++
          } else {
            failed++
            errors.push(`ID ${id}: ${result.error || 'Unknown error'}`)
          }
        } catch (error) {
          failed++
          errors.push(`ID ${id}: ${error instanceof Error ? error.message : 'Unknown error'}`)
        }
      }

      // Return summary
      if (failed === ids.length) {
        // All failed
        return c.json({
          success: false,
          error: `Failed to delete all ${failed} redirects`,
          details: errors
        }, 400)
      } else {
        // At least some succeeded
        return c.json({
          success: true,
          deleted,
          failed,
          total: ids.length,
          errors: failed > 0 ? errors : undefined
        })
      }
    } catch (error) {
      console.error('Error in bulk delete:', error)
      return c.json({ success: false, error: 'Failed to process bulk delete request' }, 500)
    }
  })

  /**
   * POST /admin/redirects/sync-cloudflare
   * Manually sync all eligible redirects to Cloudflare
   */
  admin.post('/sync-cloudflare', async (c: any) => {
    try {
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.json({ success: false, error: 'Database not available' }, 500)
      }

      const service = new RedirectService(db, c.env)

      if (!service.isCloudflareConfigured()) {
        return c.json({
          success: false,
          error: 'Cloudflare not configured. Set CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID environment variables.'
        }, 400)
      }

      const result = await service.syncAllToCloudflare()

      if (result.success) {
        return c.json({
          success: true,
          message: `Successfully synced ${result.itemsAdded} redirects to Cloudflare`,
          itemsAdded: result.itemsAdded
        })
      } else {
        return c.json({
          success: false,
          error: result.error || 'Failed to sync to Cloudflare'
        }, 500)
      }
    } catch (error) {
      console.error('Error syncing to Cloudflare:', error)
      return c.json({
        success: false,
        error: `Failed to sync: ${error instanceof Error ? error.message : 'Unknown error'}`
      }, 500)
    }
  })

  return admin
}

export default createRedirectAdminRoutes
