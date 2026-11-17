import { getCloudflareContext } from '@opennextjs/cloudflare'
import { NextResponse } from 'next/server'

interface Env {
  // Namecheap Private Email (mail.privateemail.com) — real mailbox, sent via
  // Cloudflare's TCP Sockets API (worker-mailer), not Cloudflare Email Routing.
  SMTP_HOST?: string
  SMTP_PORT?: string
  SMTP_USER?: string
  SMTP_PASS?: string
  // Recipient + sender kept server-side so the address is never published.
  SUPPORT_INBOX?: string
  SUPPORT_FROM?: string
  TURNSTILE_SECRET_KEY?: string
}

// Cloudflare's "always passes" test secret — used only when no real secret is set.
const TURNSTILE_TEST_SECRET = '1x0000000000000000000000000000000AA'
const MAX = 5_000

function clean(v: unknown, max = 500): string {
  return typeof v === 'string' ? v.trim().slice(0, max) : ''
}

function isEmail(v: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)
}

function escapeHtml(v: string): string {
  return v
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

async function verifyTurnstile(
  token: string,
  secret: string,
  ip: string | null,
): Promise<boolean> {
  const body = new FormData()
  body.append('secret', secret)
  body.append('response', token)
  if (ip) body.append('remoteip', ip)
  try {
    const res = await fetch(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      { method: 'POST', body },
    )
    const data = (await res.json()) as { success?: boolean }
    return data.success === true
  } catch {
    return false
  }
}

async function sendMail(
  env: Env,
  opts: { to: string; reply?: string; subject: string; text: string; html?: string },
) {
  if (!env.SMTP_HOST || !env.SMTP_USER || !env.SMTP_PASS) {
    throw new Error('SMTP is not configured (SMTP_HOST/SMTP_USER/SMTP_PASS missing)')
  }
  const port = Number(env.SMTP_PORT ?? '587')
  const from = env.SUPPORT_FROM ?? env.SMTP_USER

  // Deferred import: worker-mailer statically imports `cloudflare:sockets`,
  // which only exists inside workerd. A top-level import breaks Next.js's
  // build-time "collect page data" step, which requires this module in plain
  // Node. Importing it here means it's only loaded when the handler actually
  // runs (in workerd), never during the Node-based build analysis.
  const { WorkerMailer } = await import('worker-mailer/dist/index.mjs')

  const mailer = await WorkerMailer.connect({
    host: env.SMTP_HOST,
    port,
    secure: port === 465, // 465 = implicit TLS, 587 = STARTTLS
    credentials: { username: env.SMTP_USER, password: env.SMTP_PASS },
    authType: 'plain',
  })

  try {
    await mailer.send({
      from: { name: 'SonicJS Contact Form', email: from },
      to: opts.to,
      reply: opts.reply,
      subject: opts.subject,
      text: opts.text,
      html: opts.html,
    })
  } finally {
    mailer.close()
  }
}

export async function POST(request: Request) {
  let payload: Record<string, unknown>
  try {
    payload = (await request.json()) as Record<string, unknown>
  } catch {
    return NextResponse.json({ error: 'Invalid request.' }, { status: 400 })
  }

  // Honeypot — real users never fill this; bots do.
  if (clean(payload.company_website)) {
    return NextResponse.json({ ok: true })
  }

  const name = clean(payload.name)
  const email = clean(payload.email)
  const subject = clean(payload.subject, 200)
  const message = clean(payload.message, MAX)
  const turnstileToken = clean(payload.turnstileToken, 2_048)

  if (!name || !isEmail(email) || !message) {
    return NextResponse.json(
      { error: 'Name, a valid email, and a message are required.' },
      { status: 400 },
    )
  }

  const { env } = getCloudflareContext() as unknown as { env: Env }

  // Bot check — verify the Turnstile token before doing any work.
  const secret = env.TURNSTILE_SECRET_KEY ?? TURNSTILE_TEST_SECRET
  const ip = request.headers.get('CF-Connecting-IP')
  if (!turnstileToken || !(await verifyTurnstile(turnstileToken, secret, ip))) {
    return NextResponse.json(
      { error: 'Verification failed. Please retry the challenge.' },
      { status: 400 },
    )
  }

  const to = env.SUPPORT_INBOX ?? 'hello@sonicjs.com'

  const text = [
    `Name:    ${name}`,
    `Email:   ${email}`,
    `Subject: ${subject || '—'}`,
    '',
    'Message:',
    message,
  ].join('\n')

  try {
    await sendMail(env, {
      to,
      reply: email, // reply goes straight to the sender
      subject: `Contact form — ${subject || name}`,
      text,
    })
  } catch (err) {
    console.error('Failed to send contact email', err)
    return NextResponse.json(
      { error: 'We could not send your message. Please try again shortly.' },
      { status: 502 },
    )
  }

  // Confirmation to the sender — best-effort; never fails the request.
  try {
    await sendMail(env, {
      to: email,
      reply: to,
      subject: 'We received your message',
      text: [
        `Hi ${name},`,
        '',
        `Thanks for getting in touch with SonicJS. We've received your message and will reply within 1 business day.`,
        '',
        '— The SonicJS Team',
      ].join('\n'),
      html: [
        `<p>Hi ${escapeHtml(name)},</p>`,
        `<p>Thanks for getting in touch with SonicJS. We've received your message and will reply within <strong>1 business day</strong>.</p>`,
        `<p>— The SonicJS Team</p>`,
      ].join(''),
    })
  } catch (err) {
    console.error('Failed to send confirmation email', err)
  }

  return NextResponse.json({ ok: true })
}
