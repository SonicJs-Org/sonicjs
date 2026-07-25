import { getCloudflareContext } from '@opennextjs/cloudflare'
import { NextResponse } from 'next/server'

// Cloudflare Email Service binding (see wrangler.jsonc `send_email`).
interface EmailBinding {
  send(message: {
    to: string
    from: { email: string; name?: string }
    replyTo?: string
    subject: string
    text: string
    html?: string
  }): Promise<{ messageId?: string }>
}

interface Env {
  EMAIL?: EmailBinding
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

  const to = env.SUPPORT_INBOX ?? 'sales@sonicjs.com'
  const from = env.SUPPORT_FROM ?? 'noreply@sonicjs.com'

  if (!env.EMAIL) {
    console.error('EMAIL binding missing — cannot send contact message')
    return NextResponse.json(
      { error: 'Contact is temporarily unavailable. Please try again later.' },
      { status: 503 },
    )
  }

  const text = [
    `Name:    ${name}`,
    `Email:   ${email}`,
    `Subject: ${subject || '—'}`,
    '',
    'Message:',
    message,
  ].join('\n')

  try {
    await env.EMAIL.send({
      to,
      from: { email: from, name: 'SonicJS Contact Form' },
      replyTo: email, // reply goes straight to the sender
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

  return NextResponse.json({ ok: true })
}
