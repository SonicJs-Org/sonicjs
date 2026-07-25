import { type Metadata } from 'next'
import Link from 'next/link'

import { ContactForm } from '@/components/ContactForm'

export const metadata: Metadata = {
  title: 'Contact Us',
  description:
    'Get in touch with the SonicJS team — general questions, partnerships, and feedback. Community help is available on Discord and GitHub.',
}

const channels = [
  {
    title: 'Discord',
    body: 'Fastest way to get community help and chat with the team.',
    href: 'https://discord.gg/8bMy6bv3sZ',
    cta: 'Join the Discord',
  },
  {
    title: 'GitHub Discussions',
    body: 'Ask questions, request features, and browse past answers.',
    href: 'https://github.com/lane711/sonicjs/discussions',
    cta: 'Open Discussions',
  },
  {
    title: 'Commercial Support',
    body: 'Need a support SLA for your company? See paid plans.',
    href: '/commercial-support',
    cta: 'View plans',
  },
]

export default function ContactPage() {
  return (
    <div className="mx-auto max-w-5xl px-4 py-20 sm:px-6 lg:px-8">
      <div className="max-w-2xl">
        <h1 className="text-4xl font-bold tracking-tight text-zinc-900 dark:text-white">
          Contact Us
        </h1>
        <p className="mt-4 text-lg text-zinc-600 dark:text-zinc-400">
          Questions, partnerships, or feedback — send us a note and we&rsquo;ll
          reply within 1 business day. For real-time help, the community is on
          Discord and GitHub.
        </p>
      </div>

      <div className="mt-14 grid gap-12 lg:grid-cols-[1.4fr_1fr]">
        <div>
          <h2 className="text-sm font-semibold tracking-wide text-zinc-500 uppercase dark:text-zinc-400">
            Send a message
          </h2>
          <div className="mt-4">
            <ContactForm />
          </div>
        </div>

        <div>
          <h2 className="text-sm font-semibold tracking-wide text-zinc-500 uppercase dark:text-zinc-400">
            Other ways to reach us
          </h2>
          <ul className="mt-4 grid gap-4">
            {channels.map((c) => (
              <li
                key={c.title}
                className="rounded-2xl border border-zinc-900/10 bg-white p-5 dark:border-white/10 dark:bg-white/5"
              >
                <h3 className="font-semibold text-zinc-900 dark:text-white">
                  {c.title}
                </h3>
                <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
                  {c.body}
                </p>
                <Link
                  href={c.href}
                  className="mt-3 inline-block text-sm font-semibold text-emerald-600 hover:text-emerald-500 dark:text-emerald-400"
                  {...(c.href.startsWith('http')
                    ? { target: '_blank', rel: 'noopener noreferrer' }
                    : {})}
                >
                  {c.cta} →
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  )
}
