'use client'

import clsx from 'clsx'
import { useEffect, useRef, useState } from 'react'

type Status = 'idle' | 'submitting' | 'success' | 'error'

// Public site key. Override at build time with NEXT_PUBLIC_TURNSTILE_SITE_KEY.
// Fallback is Cloudflare's "always passes" test key — safe for dev/preview.
const TURNSTILE_SITE_KEY =
  process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY ?? '1x00000000000000000000AA'

const inputClasses =
  'block w-full rounded-lg border border-zinc-900/10 bg-white px-3 py-2 text-sm text-zinc-900 shadow-sm outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20 dark:border-white/10 dark:bg-white/5 dark:text-white'

function Field({
  label,
  children,
}: {
  label: string
  children: React.ReactNode
}) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-sm font-medium text-zinc-900 dark:text-white">
        {label}
      </span>
      {children}
    </label>
  )
}

export function ContactForm() {
  const [status, setStatus] = useState<Status>('idle')
  const [error, setError] = useState<string | null>(null)
  const [token, setToken] = useState<string | null>(null)
  const widgetRef = useRef<HTMLDivElement>(null)
  const renderedRef = useRef(false)

  useEffect(() => {
    function render() {
      if (renderedRef.current || !widgetRef.current || !window.turnstile) return
      renderedRef.current = true
      window.turnstile.render(widgetRef.current, {
        sitekey: TURNSTILE_SITE_KEY,
        theme: 'auto',
        callback: setToken,
        'expired-callback': () => setToken(null),
        'error-callback': () => setToken(null),
      })
    }

    if (window.turnstile) {
      render()
      return
    }
    const id = 'cf-turnstile-script'
    let script = document.getElementById(id) as HTMLScriptElement | null
    if (!script) {
      script = document.createElement('script')
      script.id = id
      script.src =
        'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'
      script.async = true
      script.defer = true
      document.head.appendChild(script)
    }
    script.addEventListener('load', render)
    return () => script?.removeEventListener('load', render)
  }, [])

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()

    if (!token) {
      setStatus('error')
      setError('Please complete the verification challenge.')
      return
    }

    setStatus('submitting')
    setError(null)

    const form = event.currentTarget
    const data = Object.fromEntries(new FormData(form).entries())
    data.turnstileToken = token

    try {
      const res = await fetch('/api/contact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      })
      if (!res.ok) {
        const body = (await res.json().catch(() => null)) as {
          error?: string
        } | null
        throw new Error(body?.error ?? 'Something went wrong. Please try again.')
      }
      setStatus('success')
      form.reset()
    } catch (err) {
      setStatus('error')
      setError(err instanceof Error ? err.message : 'Request failed.')
      setToken(null)
      window.turnstile?.reset()
    }
  }

  if (status === 'success') {
    return (
      <div className="rounded-2xl bg-emerald-50/50 p-6 text-sm text-emerald-900 ring-1 ring-emerald-500/20 ring-inset dark:bg-emerald-500/5 dark:text-emerald-200 dark:ring-emerald-500/30">
        <p className="font-semibold">Thanks — message received.</p>
        <p className="mt-1">We&rsquo;ll get back to you within 1 business day.</p>
      </div>
    )
  }

  return (
    <form onSubmit={onSubmit} className="grid gap-4">
      {/* Honeypot — hidden from users, catches bots */}
      <input
        type="text"
        name="company_website"
        tabIndex={-1}
        autoComplete="off"
        aria-hidden="true"
        className="hidden"
      />

      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Name">
          <input name="name" required className={inputClasses} />
        </Field>
        <Field label="Email">
          <input name="email" type="email" required className={inputClasses} />
        </Field>
      </div>

      <Field label="Subject">
        <input name="subject" className={inputClasses} />
      </Field>

      <Field label="Message">
        <textarea name="message" rows={5} required className={inputClasses} />
      </Field>

      <div ref={widgetRef} className="min-h-[65px]" />

      {status === 'error' && error && (
        <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
      )}

      <div>
        <button
          type="submit"
          disabled={status === 'submitting' || !token}
          className={clsx(
            'inline-flex items-center rounded-full bg-emerald-500 px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-emerald-400',
            (status === 'submitting' || !token) && 'cursor-not-allowed opacity-60',
          )}
        >
          {status === 'submitting' ? 'Sending…' : 'Send message'}
        </button>
      </div>
    </form>
  )
}
