import { type Metadata } from 'next'
import Link from 'next/link'

export const metadata: Metadata = {
  title: 'Support',
  description:
    'Get help with SonicJS — reach the community and team, or explore commercial support with a guaranteed SLA for your business.',
}

function ArrowIcon(props: React.ComponentPropsWithoutRef<'svg'>) {
  return (
    <svg viewBox="0 0 20 20" fill="none" aria-hidden="true" {...props}>
      <path
        d="M4 10h12m0 0-5-5m5 5-5 5"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

const options = [
  {
    href: '/contact',
    title: 'Contact Us',
    body: 'General questions, partnerships, or feedback. Reach the team and community — we usually reply within 1 business day.',
    cta: 'Get in touch',
  },
  {
    href: '/commercial-support',
    title: 'Commercial Support',
    body: 'A paid support contract with a guaranteed response-time SLA and a named contact — everything procurement needs to approve SonicJS. All features stay MIT.',
    cta: 'See plans & SLA',
  },
]

export default function SupportPage() {
  return (
    <div className="mx-auto max-w-5xl px-4 py-20 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-2xl text-center">
        <h1 className="text-4xl font-bold tracking-tight text-zinc-900 dark:text-white">
          How can we help?
        </h1>
        <p className="mt-4 text-lg text-zinc-600 dark:text-zinc-400">
          Choose the path that fits. Community help is always free — commercial
          support adds a contractual SLA for teams that need one.
        </p>
      </div>

      <div className="mt-14 grid gap-6 sm:grid-cols-2">
        {options.map((o) => (
          <Link
            key={o.href}
            href={o.href}
            className="group flex flex-col rounded-2xl border border-zinc-900/10 bg-white p-8 shadow-sm transition hover:border-emerald-500/40 hover:shadow-md dark:border-white/10 dark:bg-white/5"
          >
            <h2 className="text-xl font-semibold text-zinc-900 dark:text-white">
              {o.title}
            </h2>
            <p className="mt-3 flex-auto text-sm/6 text-zinc-600 dark:text-zinc-400">
              {o.body}
            </p>
            <span className="mt-6 inline-flex items-center gap-1.5 text-sm font-semibold text-emerald-600 dark:text-emerald-400">
              {o.cta}
              <ArrowIcon className="h-4 w-4 transition group-hover:translate-x-0.5" />
            </span>
          </Link>
        ))}
      </div>
    </div>
  )
}
