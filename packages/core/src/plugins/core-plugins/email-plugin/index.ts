/**
 * Email Plugin — Payload-shaped pilot port.
 *
 * Send transactional emails (Resend). Ports the legacy PluginBuilder shape to
 * definePlugin with a declarative menu entry + configSchema for the four
 * settings the admin form historically asked for.
 */

import { Hono } from 'hono'
import { definePlugin } from '../../sdk/define-plugin'

const emailRoutes = new Hono()

// POST endpoint kept for the existing JSON-shape integration. Schema-driven
// settings save flows through /admin/plugins/email/configure (P5).
emailRoutes.post('/settings', async (c: any) => {
  try {
    const body = await c.req.json()
    const db = c.env.DB

    await db.prepare(`
      UPDATE plugins
      SET settings = ?,
          updated_at = unixepoch()
      WHERE id = 'email'
    `).bind(JSON.stringify(body)).run()

    return c.json({ success: true })
  } catch (error) {
    console.error('Error saving email settings:', error)
    return c.json({ success: false, error: 'Failed to save settings' }, 500)
  }
})

emailRoutes.get('/log', async (c: any) => {
  const db = c.env.DB
  const page = Math.max(1, parseInt(c.req.query('page') ?? '1', 10))
  const pageSize = 50
  const offset = (page - 1) * pageSize

  let rows: any[] = []
  let total = 0

  try {
    const countRow = await db.prepare('SELECT COUNT(*) as n FROM email_log').first() as any
    total = countRow?.n ?? 0
    const result = await db
      .prepare(
        `SELECT id, flow, status, provider, recipient, subject, provider_id,
                delivery_state, delivery_synced_at, user_id, created_at
         FROM email_log
         ORDER BY created_at DESC
         LIMIT ? OFFSET ?`
      )
      .bind(pageSize, offset)
      .all()
    rows = (result.results ?? []) as any[]
  } catch {
    // Table may not exist yet (pre-migration) — render empty state.
  }

  const totalPages = Math.ceil(total / pageSize)

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Email Log — SonicJS Admin</title>
  <link rel="stylesheet" href="/admin/assets/css/admin.css">
  <style>
    .email-log-table { width: 100%; border-collapse: collapse; font-size: 13px; }
    .email-log-table th, .email-log-table td { padding: 8px 10px; border-bottom: 1px solid #e5e7eb; text-align: left; }
    .email-log-table th { background: #f9fafb; font-weight: 600; }
    .badge { padding: 2px 8px; border-radius: 9999px; font-size: 11px; font-weight: 600; }
    .badge-sent { background: #dcfce7; color: #166534; }
    .badge-failed { background: #fee2e2; color: #991b1b; }
    .badge-pending { background: #fef9c3; color: #854d0e; }
    .delivery-ok { color: #16a34a; }
    .delivery-fail { color: #dc2626; }
    .pagination { display: flex; gap: 8px; padding: 16px 0; }
    .pagination a { padding: 4px 12px; border: 1px solid #d1d5db; border-radius: 4px; text-decoration: none; color: #374151; }
    .pagination a.active { background: #2563eb; color: #fff; border-color: #2563eb; }
    .empty-state { padding: 40px; text-align: center; color: #6b7280; }
  </style>
</head>
<body>
  <div style="padding: 24px; max-width: 1200px; margin: 0 auto;">
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 24px;">
      <a href="/admin/plugins/email/configure" style="color: #6b7280; text-decoration: none;">← Email Settings</a>
      <h1 style="margin: 0; font-size: 20px; font-weight: 700;">Email Log</h1>
      <span style="color: #6b7280; font-size: 14px;">${total.toLocaleString()} total sends</span>
    </div>

    ${rows.length === 0 ? `
      <div class="empty-state">
        <p>No emails logged yet. Email sends are recorded here once the email_log table is migrated.</p>
        <p style="margin-top: 8px; font-size: 12px; color: #9ca3af;">Run migration 037 (and 038 for delivery columns) if the table is missing.</p>
      </div>
    ` : `
      <table class="email-log-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Flow</th>
            <th>Recipient</th>
            <th>Subject</th>
            <th>Provider</th>
            <th>Status</th>
            <th>Delivery</th>
            <th>User</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map((r: any) => {
            const ts = r.created_at ? new Date(r.created_at).toLocaleString() : '—'
            const deliveryBadge = r.delivery_state
              ? `<span class="${r.delivery_state === 'delivered' ? 'delivery-ok' : 'delivery-fail'}">${r.delivery_state}</span>`
              : '<span style="color:#9ca3af">—</span>'
            const statusClass = r.status === 'sent' ? 'badge-sent' : r.status === 'failed' ? 'badge-failed' : 'badge-pending'
            return `<tr>
              <td style="white-space:nowrap;color:#6b7280;font-size:12px">${ts}</td>
              <td>${r.flow ?? '—'}</td>
              <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${r.recipient ?? '—'}</td>
              <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${r.subject ?? '—'}</td>
              <td>${r.provider ?? '—'}</td>
              <td><span class="badge ${statusClass}">${r.status ?? '—'}</span></td>
              <td>${deliveryBadge}</td>
              <td style="font-size:12px;color:#6b7280">${r.user_id ?? '—'}</td>
            </tr>`
          }).join('')}
        </tbody>
      </table>

      ${totalPages > 1 ? `
        <div class="pagination">
          ${Array.from({ length: totalPages }, (_, i) => i + 1).map((p) =>
            `<a href="?page=${p}" class="${p === page ? 'active' : ''}">${p}</a>`
          ).join('')}
        </div>
      ` : ''}
    `}
  </div>
</body>
</html>`

  return c.html(html)
})

emailRoutes.get('/log/api', async (c: any) => {
  const db = c.env.DB
  const limit = Math.min(200, parseInt(c.req.query('limit') ?? '50', 10))
  const offset = Math.max(0, parseInt(c.req.query('offset') ?? '0', 10))
  const flow = c.req.query('flow')
  const status = c.req.query('status')

  try {
    const conditions: string[] = []
    const params: unknown[] = []
    if (flow) { conditions.push('flow = ?'); params.push(flow) }
    if (status) { conditions.push('status = ?'); params.push(status) }
    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : ''

    const rows = await db
      .prepare(`SELECT * FROM email_log ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`)
      .bind(...params, limit, offset)
      .all()

    return c.json({ data: rows.results ?? [], limit, offset })
  } catch (err) {
    return c.json({ error: 'email_log not available', details: String(err) }, 503)
  }
})

emailRoutes.post('/test', async (c: any) => {
  try {
    const db = c.env.DB
    const body = await c.req.json()

    const plugin = await db.prepare(`
      SELECT settings FROM plugins WHERE id = 'email'
    `).first() as { settings: string | null } | null

    if (!plugin?.settings) {
      return c.json({
        success: false,
        error: 'Email settings not configured. Please save your settings first.',
      }, 400)
    }

    const settings = JSON.parse(plugin.settings)
    if (!settings.apiKey || !settings.fromEmail || !settings.fromName) {
      return c.json({
        success: false,
        error: 'Missing required settings. Please configure API Key, From Email, and From Name.',
      }, 400)
    }

    const toEmail = body.toEmail || settings.fromEmail
    if (!toEmail.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
      return c.json({ success: false, error: 'Invalid email address format' }, 400)
    }

    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${settings.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: `${settings.fromName} <${settings.fromEmail}>`,
        to: [toEmail],
        subject: 'Test Email from SonicJS',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h1 style="color: #667eea;">Test Email Successful! 🎉</h1>
            <p>This is a test email from your SonicJS Email plugin.</p>
            <p><strong>Configuration:</strong></p>
            <ul>
              <li>From: ${settings.fromName} &lt;${settings.fromEmail}&gt;</li>
              <li>Reply-To: ${settings.replyTo || 'Not set'}</li>
              <li>Sent at: ${new Date().toISOString()}</li>
            </ul>
            <p>Your email settings are working correctly!</p>
          </div>
        `,
        reply_to: settings.replyTo || settings.fromEmail,
      }),
    })

    const data = await response.json() as any

    if (!response.ok) {
      console.error('Resend API error:', data)
      return c.json({
        success: false,
        error: data.message || 'Failed to send test email. Check your API key and domain verification.',
      }, response.status)
    }

    return c.json({
      success: true,
      message: `Test email sent successfully to ${toEmail}`,
      emailId: data.id,
    })
  } catch (error: any) {
    console.error('Test email error:', error)
    return c.json({
      success: false,
      error: error.message || 'An error occurred while sending test email',
    }, 500)
  }
})

export const emailPlugin = definePlugin({
  id: 'email',
  version: '1.0.0',
  name: 'Email',
  description: 'Send transactional emails using Resend.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS Team', email: 'team@sonicjs.com' },
  capabilities: ['email:send'],

  register(app) {
    app.route('/admin/plugins/email', emailRoutes)
  },

  menu: [
    {
      label: 'Email',
      path: '/admin/plugins/email/configure',
      icon: 'envelope',
      order: 80,
      permissions: ['email:manage'],
    },
  ],

  configSchema: {
    apiKey: {
      type: 'string',
      label: 'Resend API Key',
      sensitive: true,
      required: true,
      placeholder: 're_xxxxxxxxxxxx',
      description: 'Sign up at resend.com and create a server-side API key.',
    },
    fromEmail: {
      type: 'string',
      label: 'From Email',
      format: 'email',
      required: true,
      placeholder: 'noreply@example.com',
    },
    fromName: {
      type: 'string',
      label: 'From Name',
      required: true,
      placeholder: 'SonicJS',
      default: 'SonicJS',
    },
    replyTo: {
      type: 'string',
      label: 'Reply-To (optional)',
      format: 'email',
      placeholder: 'support@example.com',
    },
  },

  activate: async () => {
    console.info('✅ Email plugin activated')
  },
  deactivate: async () => {
    console.info('❌ Email plugin deactivated')
  },
})

export function createEmailPlugin() {
  return emailPlugin
}
