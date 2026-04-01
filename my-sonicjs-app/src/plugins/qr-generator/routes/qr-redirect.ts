import { Hono } from 'hono'
import type { D1Database } from '@cloudflare/workers-types'
import type { Context } from 'hono'

/**
 * QR Code Redirect Route Handler
 *
 * Handles /qr/:code requests:
 * - Active QR codes: 302 redirect to destination URL
 * - Deleted/inactive QR codes: 410 Gone with branded expired page
 * - Unknown codes: 404 Not Found
 *
 * Note: Redirect analytics are tracked by the redirect-management middleware.
 * This handler ensures QR-specific routes work correctly with proper status codes.
 */

/**
 * Create the QR redirect route handler
 * Returns a Hono app that handles /qr/:code requests
 */
export function createQRRedirectHandler(): Hono {
  const app = new Hono()

  app.get('/qr/:code', async (c: Context) => {
    const code = c.req.param('code')
    // Get database from context - SonicJS provides db via c.get('db') or c.env.DB
    const db: D1Database = (c.get('db') || (c.env as any)?.DB) as D1Database

    if (!db) {
      console.error('[QR Redirect] Database not available')
      return c.notFound()
    }

    // Query redirect by source path
    // The redirect was created by QR generator with source = /qr/{code}
    const redirect = await db
      .prepare(`
        SELECT destination, deleted_at, is_active
        FROM redirects
        WHERE source = ?
        LIMIT 1
      `)
      .bind(`/qr/${code}`)
      .first()

    // No redirect exists - 404
    if (!redirect) {
      return c.notFound()
    }

    // Soft-deleted or inactive - show expired page with 410 Gone
    if (redirect.deleted_at || redirect.is_active === 0) {
      return c.html(expiredQRPage(), 410)
    }

    // Active redirect - 302 to destination
    // Using 302 (temporary) allows destination changes without cache issues
    return c.redirect(redirect.destination as string, 302)
  })

  return app
}

/**
 * Generate the expired QR code page HTML
 * Returns a branded, user-friendly page for expired/deleted QR codes
 *
 * Design:
 * - Gradient background matching QR generator branding
 * - Clean card layout with warning icon
 * - Clear messaging about expired status
 * - Responsive and accessible
 */
function expiredQRPage(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>QR Code Expired</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 16px;
      padding: 48px;
      max-width: 480px;
      text-align: center;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
    }
    .icon {
      width: 80px;
      height: 80px;
      margin: 0 auto 24px;
      background: #f3f4f6;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .icon svg {
      width: 40px;
      height: 40px;
      color: #6b7280;
    }
    h1 {
      color: #1f2937;
      font-size: 24px;
      font-weight: 600;
      margin-bottom: 12px;
    }
    p {
      color: #6b7280;
      font-size: 16px;
      line-height: 1.6;
      margin-bottom: 8px;
    }
    .help {
      margin-top: 24px;
      padding-top: 24px;
      border-top: 1px solid #e5e7eb;
      font-size: 14px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">
      <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
    </div>
    <h1>QR Code Expired</h1>
    <p>This QR code is no longer active.</p>
    <p>The content it linked to has been removed or is no longer available.</p>
    <div class="help">
      <p>If you believe this is an error, please contact the site administrator.</p>
    </div>
  </div>
</body>
</html>`
}

export default createQRRedirectHandler()
