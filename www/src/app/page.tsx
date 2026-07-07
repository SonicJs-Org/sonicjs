import Image from 'next/image'
import Link from 'next/link'
import { CopyCommand } from '@/components/CopyCommand'

function GridBackdrop({ patternId }: { patternId: string }) {
  return (
    <svg
      aria-hidden="true"
      className="absolute inset-0 -z-10 size-full stroke-white/10 [mask-image:radial-gradient(100%_100%_at_top_right,white,transparent)]"
    >
      <defs>
        <pattern
          id={patternId}
          width="200"
          height="200"
          x="50%"
          y="-1"
          patternUnits="userSpaceOnUse"
        >
          <path d="M.5 200V.5H200" fill="none" />
        </pattern>
      </defs>
      <svg x="50%" y="-1" className="overflow-visible fill-gray-800/20">
        <path
          d="M-200 0h201v201h-201Z M600 0h201v201h-201Z M-400 600h201v201h-201Z M200 800h201v201h-201Z"
          strokeWidth="0"
        />
      </svg>
      <rect width="100%" height="100%" fill={`url(#${patternId})`} strokeWidth="0" />
    </svg>
  )
}

function GlowBlob({ className }: { className?: string }) {
  return (
    <div aria-hidden="true" className={className}>
      <div
        style={{
          clipPath:
            'polygon(73.6% 51.7%, 91.7% 11.8%, 100% 46.4%, 97.4% 82.2%, 92.5% 84.9%, 75.7% 64%, 55.3% 47.5%, 46.5% 49.4%, 45% 62.9%, 50.3% 87.2%, 21.3% 64.1%, 0.1% 100%, 5.4% 51.1%, 21.4% 63.9%, 58.9% 0.2%, 73.6% 51.7%)',
        }}
        className="aspect-[1108/632] w-[69.25rem] flex-none bg-gradient-to-r from-[#67e8f9] to-[#0891b2] opacity-20"
      />
    </div>
  )
}

function FeatureIcon({ d }: { d: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      aria-hidden="true"
      className="size-6 text-white"
    >
      <path d={d} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function SectionHeader({
  eyebrow,
  title,
  lede,
  align = 'center',
}: {
  eyebrow: string
  title: string
  lede?: React.ReactNode
  align?: 'center' | 'left'
}) {
  return (
    <div
      className={
        align === 'center' ? 'mx-auto max-w-2xl text-center' : 'mx-auto max-w-2xl lg:mx-0'
      }
    >
      <p className="text-base/7 font-semibold text-cyan-400">{eyebrow}</p>
      <h2 className="mt-2 text-pretty text-4xl font-semibold tracking-tight text-white sm:text-5xl">
        {title}
      </h2>
      {lede ? <p className="mt-6 text-lg/8 text-gray-300">{lede}</p> : null}
    </div>
  )
}

const ICONS = {
  globe:
    'M12 21a9.004 9.004 0 0 0 8.716-6.747M12 21a9.004 9.004 0 0 1-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 0 1 7.843 4.582M12 3a8.997 8.997 0 0 0-7.843 4.582m15.686 0A11.953 11.953 0 0 1 12 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0 1 21 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0 1 12 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 0 1 3 12c0-1.605.42-3.113 1.157-4.418',
  lockOpen:
    'M13.5 10.5V6.75a4.5 4.5 0 1 1 9 0v3.75M3.75 21.75h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H3.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z',
  arrowsRightLeft:
    'M7.5 21 3 16.5m0 0L7.5 12M3 16.5h13.5m0-13.5L21 7.5m0 0L16.5 12M21 7.5H7.5',
  sparkles:
    'M9.813 15.904 9 18.75l-.813-2.846a4.5 4.5 0 0 0-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 0 0 3.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 0 0 3.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 0 0-3.09 3.09ZM18.259 8.715 18 9.75l-.259-1.035a3.375 3.375 0 0 0-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 0 0 2.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 0 0 2.456 2.456L21.75 6l-1.035.259a3.375 3.375 0 0 0-2.456 2.456ZM16.894 20.567 16.5 21.75l-.394-1.183a2.25 2.25 0 0 0-1.423-1.423L13.5 18.75l1.183-.394a2.25 2.25 0 0 0 1.423-1.423l.394-1.183.394 1.183a2.25 2.25 0 0 0 1.423 1.423l1.183.394-1.183.394a2.25 2.25 0 0 0-1.423 1.423Z',
  puzzle:
    'M14.25 6.087c0-.355.186-.676.401-.959.221-.29.349-.634.349-1.003 0-1.036-1.007-1.875-2.25-1.875s-2.25.84-2.25 1.875c0 .369.128.713.349 1.003.215.283.401.604.401.959v0a.64.64 0 0 1-.657.643 48.39 48.39 0 0 1-4.163-.3c.186 1.613.293 3.25.315 4.907a.656.656 0 0 1-.658.663v0c-.355 0-.676-.186-.959-.401a1.647 1.647 0 0 0-1.003-.349c-1.036 0-1.875 1.007-1.875 2.25s.84 2.25 1.875 2.25c.369 0 .713-.128 1.003-.349.283-.215.604-.401.959-.401v0c.31 0 .555.26.532.57a48.039 48.039 0 0 1-.642 5.056c1.518.19 3.058.309 4.616.354a.64.64 0 0 0 .657-.643v0c0-.355-.186-.676-.401-.959a1.647 1.647 0 0 1-.349-1.003c0-1.035 1.008-1.875 2.25-1.875 1.243 0 2.25.84 2.25 1.875 0 .369-.128.713-.349 1.003-.215.283-.4.604-.4.959v0c0 .333.277.599.61.58a48.1 48.1 0 0 0 5.427-.63 48.05 48.05 0 0 0 .582-4.717.532.532 0 0 0-.533-.57v0c-.355 0-.676.186-.959.401-.29.221-.634.349-1.003.349-1.035 0-1.875-1.007-1.875-2.25s.84-2.25 1.875-2.25c.37 0 .713.128 1.003.349.283.215.604.401.96.401v0a.656.656 0 0 0 .658-.663 48.422 48.422 0 0 0-.37-5.36c-1.886.342-3.81.574-5.766.689a.578.578 0 0 1-.61-.58v0Z',
  magnifier: 'm21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z',
  pencil:
    'm16.862 4.487 1.687-1.688a1.875 1.875 0 1 1 2.652 2.652L10.582 16.07a4.5 4.5 0 0 1-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 0 1 1.13-1.897l8.932-8.931Zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0 1 15.75 21H5.25A2.25 2.25 0 0 1 3 18.75V8.25A2.25 2.25 0 0 1 5.25 6H10',
  fingerprint:
    'M7.864 4.243A7.5 7.5 0 0 1 19.5 10.5c0 2.92-.556 5.709-1.568 8.268M5.742 6.364A7.465 7.465 0 0 0 4.5 10.5a7.464 7.464 0 0 1-1.15 3.993m1.989 3.559A11.209 11.209 0 0 0 8.25 10.5a3.75 3.75 0 1 1 7.5 0c0 .527-.021 1.049-.064 1.565M12 10.5a14.94 14.94 0 0 1-3.6 9.75m6.633-4.596a18.666 18.666 0 0 1-2.485 5.33',
  bolt: 'm3.75 13.5 10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75Z',
  arrowPath:
    'M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0 3.181 3.183a8.25 8.25 0 0 0 13.803-3.7M4.031 9.865a8.25 8.25 0 0 1 13.803-3.7l3.181 3.182m0-4.991v4.99',
}

export default function HomePage() {
  return (
    <div className="bg-gray-900">
      {/* ── Hero ── */}
      <div className="relative isolate overflow-hidden">
        <GridBackdrop patternId="hero-grid-pattern" />
        <GlowBlob className="absolute left-[calc(50%-4rem)] top-10 -z-10 transform-gpu blur-3xl sm:left-[calc(50%-18rem)] lg:left-48 lg:top-[calc(50%-30rem)] xl:left-[calc(50%-24rem)]" />
        <div className="mx-auto max-w-7xl px-6 pb-24 pt-10 sm:pb-32 lg:flex lg:px-8 lg:py-40">
          <div className="mx-auto max-w-2xl shrink-0 lg:mx-0 lg:pt-8">
            <div className="mt-8 sm:mt-12 lg:mt-0">
              <Link href="/changelog" className="inline-flex space-x-6 no-underline">
                <span className="rounded-full bg-cyan-500/10 px-3 py-1 text-sm/6 font-semibold text-cyan-400 ring-1 ring-inset ring-cyan-500/25">
                  What&apos;s new
                </span>
                <span className="inline-flex items-center space-x-2 text-sm/6 font-medium text-gray-300">
                  <span>Just shipped v3.0.0-beta</span>
                  <svg
                    viewBox="0 0 20 20"
                    fill="currentColor"
                    aria-hidden="true"
                    className="size-5 text-gray-500"
                  >
                    <path
                      d="M8.22 5.22a.75.75 0 0 1 1.06 0l4.25 4.25a.75.75 0 0 1 0 1.06l-4.25 4.25a.75.75 0 0 1-1.06-1.06L11.94 10 8.22 6.28a.75.75 0 0 1 0-1.06Z"
                      clipRule="evenodd"
                      fillRule="evenodd"
                    />
                  </svg>
                </span>
              </Link>
            </div>
            <h1 className="mt-10 text-pretty text-5xl font-semibold tracking-tight text-white sm:text-7xl">
              The only headless CMS born on the edge.
            </h1>
            <p className="mt-8 text-pretty text-lg font-medium text-gray-400 sm:text-xl/8">
              Zero cold starts, anywhere on Earth. 100% MIT open source, every feature free. Built
              for Cloudflare Workers — and runs on Docker, your VPS, anywhere SQLite runs.
            </p>
            <div className="mt-10 flex flex-wrap items-center gap-4">
              <a
                href="https://demo.sonicjs.com"
                target="_blank"
                rel="noopener noreferrer"
                className="rounded-md bg-cyan-500 px-3.5 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-cyan-400 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-500 no-underline"
              >
                Try live demo
              </a>
              <Link
                href="/quickstart"
                className="rounded-md bg-white/10 px-3.5 py-2.5 text-sm font-semibold text-white shadow-sm ring-1 ring-inset ring-white/20 hover:bg-white/20 no-underline"
              >
                Start building
              </Link>
              <Link
                href="https://github.com/lane711/sonicjs"
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm/6 font-semibold text-white no-underline"
              >
                Star on GitHub <span aria-hidden="true">→</span>
              </Link>
            </div>
            <p className="mt-3 text-xs text-gray-500">
              No signup required — instant access to real admin
            </p>
            <CopyCommand command="npx create-sonicjs@latest my-app" className="mt-8" />
            <div className="mt-6 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-gray-500">
              <span>MIT licensed</span>
              <span aria-hidden="true">·</span>
              <span>330+ edge cities</span>
              <span aria-hidden="true">·</span>
              <span>$0 to start</span>
              <span aria-hidden="true">·</span>
              <span>TypeScript-first</span>
              <span aria-hidden="true">·</span>
              <span>Runs anywhere</span>
            </div>
          </div>
          <div className="mx-auto mt-16 flex max-w-2xl sm:mt-24 lg:ml-10 lg:mr-0 lg:mt-0 lg:max-w-none lg:flex-none xl:ml-32">
            <div className="max-w-3xl flex-none sm:max-w-5xl lg:max-w-none">
              <div className="-m-2 rounded-xl bg-white/[0.025] p-2 ring-1 ring-inset ring-white/10 lg:-m-4 lg:rounded-2xl lg:p-4">
                <Image
                  src="/images/home/admin-screenshot.png"
                  alt="SonicJS admin content management interface"
                  width={3360}
                  height={2100}
                  className="w-[76rem] rounded-md bg-white/5 shadow-2xl ring-1 ring-white/10"
                  priority
                />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── AI section ── */}
      <div className="mx-auto mt-0 mb-24 max-w-7xl px-6 sm:mb-32 lg:mb-40 lg:px-8">
        <div className="rounded-3xl bg-gradient-to-br from-cyan-950/80 via-gray-900 to-gray-900 p-8 ring-1 ring-cyan-500/30 sm:p-12">
          <div className="flex flex-col lg:flex-row lg:items-center lg:gap-16">
            <div className="flex-1">
              <div className="mb-4 inline-flex items-center gap-2 rounded-full bg-cyan-500/10 px-3 py-1 text-sm font-semibold text-cyan-400 ring-1 ring-inset ring-cyan-500/25">
                AI-native
              </div>
              <h2 className="text-pretty text-4xl font-semibold tracking-tight text-white sm:text-5xl">
                Your content layer, speaking AI.
              </h2>
              <p className="mt-6 text-lg/8 text-gray-300">
                In 2026 every CMS claims AI. SonicJS ships it: a native Model Context Protocol
                (MCP) server your agents connect to directly, RAG-powered semantic search, and an
                AI-friendly API structure your LLM tools already understand.
              </p>
              <ul className="mt-8 space-y-4 text-sm/6 text-gray-300">
                <li className="flex items-start gap-3">
                  <span aria-hidden="true" className="mt-0.5 text-cyan-400">✦</span>
                  <span>
                    <strong className="font-semibold text-white">Native MCP server</strong> —
                    auto-generated tools let Claude Code, Cursor &amp; VS Code read, create, and
                    publish your content. Secure scoped API keys; respects your existing
                    permissions.
                  </span>
                </li>
                <li className="flex items-start gap-3">
                  <span aria-hidden="true" className="mt-0.5 text-cyan-400">✦</span>
                  <span>
                    <strong className="font-semibold text-white">Semantic search</strong> —
                    RAG-powered via Cloudflare Vectorize. Natural language queries, zero extra
                    infra.
                  </span>
                </li>
                <li className="flex items-start gap-3">
                  <span aria-hidden="true" className="mt-0.5 text-cyan-400">✦</span>
                  <span>
                    <strong className="font-semibold text-white">Agent-ready API</strong> —
                    structured schema, consistent REST surface, auto-generated docs. LLMs
                    understand it out of the box.
                  </span>
                </li>
              </ul>
              <p className="mt-8">
                <Link
                  href="/plugins/ai-search"
                  className="text-sm/6 font-semibold text-cyan-400 hover:text-cyan-300 no-underline"
                >
                  Explore AI features <span aria-hidden="true">→</span>
                </Link>
              </p>
            </div>
            <div className="mt-10 shrink-0 lg:mt-0 lg:w-96">
              <div className="overflow-hidden rounded-2xl bg-gray-950/60 ring-1 ring-cyan-500/30">
                <div className="flex items-center gap-2 border-b border-cyan-500/20 bg-white/5 px-4 py-3">
                  <span className="text-xs font-medium text-cyan-400">
                    Connect Claude Code / Cursor
                  </span>
                </div>
                <pre className="m-0 overflow-x-auto p-5 text-xs leading-relaxed text-cyan-200">{`// Point your agent at your CMS
{
  "mcpServers": {
    "sonicjs": {
      "url": "https://your-site.com/api/mcp",
      "headers": {
        "Authorization": "Bearer <mcp-key>"
      }
    }
  }
}`}</pre>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Benchmark stats ── */}
      <div className="mx-auto max-w-7xl px-6 lg:px-8">
        <div className="mx-auto max-w-2xl lg:mx-0 lg:max-w-xl">
          <p className="text-base/7 font-semibold text-cyan-400">Performance by architecture</p>
          <h2 className="mt-2 text-pretty text-4xl font-semibold tracking-tight text-white sm:text-5xl">
            Numbers a single region can&apos;t match
          </h2>
          <p className="mt-6 text-lg/8 text-gray-300">
            Every request runs in the city closest to your user. These aren&apos;t optimizations —
            they&apos;re what the architecture does by default.
          </p>
        </div>
        <dl className="mx-auto mt-16 grid max-w-2xl grid-cols-1 gap-x-8 gap-y-10 text-white sm:grid-cols-2 lg:mx-0 lg:max-w-none lg:grid-cols-4">
          {[
            { value: '0-5ms', label: 'Cold start', context: 'vs 500–2000ms on Node.js CMSs' },
            { value: '15-50ms', label: 'API response', context: 'vs 1–4s with relations elsewhere' },
            { value: '300+', label: 'Edge locations', context: 'vs one region, one continent' },
            {
              value: '$0',
              label: 'To start',
              context: "Cloudflare's free tier covers 100k requests/day",
            },
          ].map((stat) => (
            <div key={stat.label} className="flex flex-col gap-y-2 border-l border-white/10 pl-6">
              <dt className="text-sm/6 font-semibold text-white">{stat.label}</dt>
              <dd className="order-first text-4xl font-semibold tracking-tight">{stat.value}</dd>
              <dd className="text-sm/6 text-gray-400">{stat.context}</dd>
            </div>
          ))}
        </dl>
      </div>

      {/* ── Why developers switch (the wedge) ── */}
      <div className="mx-auto mt-24 max-w-7xl px-6 sm:mt-40 lg:px-8">
        <SectionHeader
          eyebrow="The escape hatch"
          title="Why developers switch to SonicJS"
          lede={
            <>
              Migration hell. $99/mo paywalls. Single-region latency. Cold-start lag. You&apos;ve
              felt these. Here&apos;s the escape.
            </>
          }
        />
        <div className="mx-auto mt-16 grid max-w-2xl grid-cols-1 gap-8 md:grid-cols-2 lg:max-w-none">
          {[
            {
              icon: ICONS.arrowsRightLeft,
              accent: 'text-cyan-400',
              title: 'No More Migration Hell',
              body: (
                <>
                  &ldquo;Upgrading from Strapi v4 → v5 alone took approximately{' '}
                  <strong className="text-pink-300">40 hours</strong>&rdquo; with 50+ breaking
                  changes documented.
                </>
              ),
              footer:
                'SonicJS: semantic versioning with automatic, versioned migrations — upgrades stay boring.',
            },
            {
              icon: ICONS.lockOpen,
              accent: 'text-emerald-400',
              title: 'The Features You Need Are Paywalled',
              body: (
                <>
                  Strapi gates{' '}
                  <strong className="text-pink-300">
                    version history, scheduled publishing, Live Preview, audit logs & SSO
                  </strong>{' '}
                  behind $99+/mo tiers. Contentful&apos;s real features start near $300/mo.
                </>
              ),
              footer:
                'SonicJS: every feature in the MIT core. No Growth tier. No Enterprise gate. Ever.',
            },
            {
              icon: ICONS.bolt,
              accent: 'text-amber-400',
              title: '0ms Cold Start, Sub-50ms Worldwide',
              body: (
                <>
                  Single-region Node CMSs charge you twice:{' '}
                  <strong className="text-pink-300">500-2000ms</strong> cold boots after idle, then{' '}
                  <strong className="text-pink-300">200-500ms</strong> of round-trip for every user
                  an ocean away from your server.
                </>
              ),
              footer:
                'SonicJS: V8 isolates in 300+ edge cities — no boot penalty, responses served near the user.',
            },
            {
              icon: ICONS.sparkles,
              accent: 'text-fuchsia-400',
              title: 'AI Included, Not Upsold',
              body: (
                <>
                  Strapi and Contentful gate AI behind{' '}
                  <strong className="text-pink-300">paid tiers</strong>; Payload and Directus
                  don&apos;t ship it at all. In 2026 your CMS should talk to your agents.
                </>
              ),
              footer:
                'SonicJS: AI search + a native MCP server in the free core — Claude Code & Cursor connect directly.',
            },
          ].map((card) => (
            <div
              key={card.title}
              className="group relative flex min-h-[18rem] flex-col overflow-hidden rounded-2xl bg-white/[0.02] p-8 ring-1 ring-white/10 transition-all duration-300 hover:bg-white/[0.04] hover:ring-white/20"
            >
              <div
                className={`mb-6 flex size-11 items-center justify-center rounded-xl bg-white/5 ring-1 ring-white/10 ${card.accent}`}
              >
                <FeatureIcon d={card.icon} />
              </div>
              <h3 className="mb-3 text-xl font-semibold text-white">{card.title}</h3>
              <p className="mb-4 flex-auto text-sm/6 text-gray-300">{card.body}</p>
              <p className="border-t border-white/10 pt-4 text-sm/6 font-medium text-cyan-300">
                {card.footer}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* ── Four pillars ── */}
      <div className="mx-auto mt-24 max-w-7xl px-6 sm:mt-40 lg:px-8">
        <SectionHeader
          eyebrow="Why SonicJS"
          title="Fast because it's edge-native. Free because it's truly open."
          lede="Speed and freedom are the two things every competitor makes you choose between. SonicJS refuses the trade."
        />
        <div className="mx-auto mt-16 max-w-2xl sm:mt-20 lg:mt-24 lg:max-w-none">
          <dl className="grid max-w-xl grid-cols-1 gap-x-8 gap-y-16 sm:grid-cols-2 lg:max-w-none lg:grid-cols-4">
            {[
              {
                icon: ICONS.globe,
                title: 'Edge-native, zero cold start',
                desc: 'Runs in 300+ Cloudflare cities. 0–5ms cold start vs 100–2000ms on Node.js. No regions to configure — global by default.',
              },
              {
                icon: ICONS.lockOpen,
                title: '100% MIT, every feature free',
                desc: 'Version history, SSO, RBAC, workflows — all included, forever. No open-core bait. No per-seat pricing. No Enterprise gate.',
              },
              {
                icon: ICONS.arrowsRightLeft,
                title: 'Independent & portable',
                desc: 'No VC clock. No license rug-pull. No infra lock-in — run the same code on Cloudflare, Docker, or your own VPS. Not captive to a vendor, including us.',
              },
              {
                icon: ICONS.sparkles,
                title: 'Code-first DX + AI-native',
                desc: 'TypeScript end-to-end, schema-as-code, auto-generated REST API — plus a native MCP server so Claude Code, Cursor & VS Code read and manage your content directly.',
              },
            ].map((pillar) => (
              <div key={pillar.title} className="flex flex-col">
                <dt className="text-base/7 font-semibold text-white">
                  <div className="mb-6 flex size-10 items-center justify-center rounded-lg bg-cyan-500">
                    <FeatureIcon d={pillar.icon} />
                  </div>
                  {pillar.title}
                </dt>
                <dd className="mt-1 flex flex-auto flex-col text-base/7 text-gray-400">
                  <p className="flex-auto">{pillar.desc}</p>
                </dd>
              </div>
            ))}
          </dl>
        </div>
      </div>

      {/* ── Comparison table ── */}
      <div className="mx-auto mt-24 max-w-7xl px-6 sm:mt-40 lg:px-8">
        <SectionHeader
          eyebrow="Proof, not promises"
          title="Honest numbers. No marketing spin."
          lede={
            <>
              Real benchmarks, real pricing. We also publish what SonicJS isn&apos;t great at yet —
              because devs who read the fine print are the ones worth earning.{' '}
              <Link href="/compare" className="font-semibold text-cyan-400 hover:text-cyan-300">
                Full comparison →
              </Link>
            </>
          }
        />
        <div className="mx-auto mt-16 max-w-2xl overflow-x-auto rounded-2xl ring-1 ring-white/10 lg:max-w-none">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="bg-white/5">
                <th className="border-b border-white/10 p-4 text-left font-semibold text-white">
                  Metric
                </th>
                <th className="border-b border-white/10 p-4 text-center font-semibold text-cyan-400">
                  SonicJS
                </th>
                <th className="border-b border-white/10 p-4 text-center font-semibold text-gray-400">
                  Strapi
                </th>
                <th className="border-b border-white/10 p-4 text-center font-semibold text-gray-400">
                  Payload
                </th>
                <th className="border-b border-white/10 p-4 text-center font-semibold text-gray-400">
                  Directus
                </th>
              </tr>
            </thead>
            <tbody>
              {[
                ['Cold Start Time', '0-5ms', '500-2000ms', '100-300ms', '300-1000ms'],
                ['API Response (with relations)', '15-50ms', '1-4s', '1-6s', '1.5-5s'],
                ['Cross-Region Latency', '30-60ms', '300-800ms', '250-600ms', '300-800ms'],
                ['Edge Locations', '300+', '1', '1', '1'],
                ['Dev Server Startup', '2-5s', '10-30s', '15-60s', '5-15s'],
                ['Cloud Hosting', 'Free*', '$99+/mo', '$35+/mo', '$99+/mo'],
              ].map(([metric, sonic, strapi, payload, directus], i, arr) => {
                const border = i < arr.length - 1 ? 'border-b border-white/5' : ''
                return (
                  <tr key={metric} className="hover:bg-white/5">
                    <td className={`p-4 font-medium text-white ${border}`}>{metric}</td>
                    <td className={`p-4 text-center font-semibold text-cyan-400 ${border}`}>
                      {sonic}
                    </td>
                    <td className={`p-4 text-center text-gray-400 ${border}`}>{strapi}</td>
                    <td className={`p-4 text-center text-gray-400 ${border}`}>{payload}</td>
                    <td className={`p-4 text-center text-gray-400 ${border}`}>{directus}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
        <p className="mt-4 text-center text-xs text-gray-500">
          *Cloudflare free tier: 100k requests/day, 5GB D1 storage, 5M reads/day. $5/mo for higher
          traffic.{' '}
          <Link
            href="/blog/strapi-vs-payload-vs-sonicjs"
            className="underline hover:text-gray-300"
          >
            See comparison posts for sources
          </Link>
          .
        </p>
      </div>

      {/* ── DX showcase ── */}
      <div className="mx-auto mt-24 max-w-7xl px-6 sm:mt-40 lg:px-8">
        <SectionHeader
          eyebrow="Developer experience"
          title="From schema to global API in minutes"
          lede="Define your content model in TypeScript. SonicJS generates the REST API and the admin UI. Deploy with one command."
        />
        <div className="mx-auto mt-16 grid max-w-2xl grid-cols-1 gap-8 lg:max-w-none lg:grid-cols-2">
          <div className="overflow-hidden rounded-2xl bg-white/5 ring-1 ring-white/10">
            <div className="flex items-center gap-3 border-b border-white/10 bg-white/5 px-4 py-3">
              <div className="flex gap-1.5">
                <span className="size-2.5 rounded-full bg-red-500/60" />
                <span className="size-2.5 rounded-full bg-amber-500/60" />
                <span className="size-2.5 rounded-full bg-emerald-500/60" />
              </div>
              <span className="text-xs font-medium text-gray-400">
                1 · Define your schema
              </span>
            </div>
            <pre className="m-0 overflow-x-auto p-6 text-sm leading-relaxed text-gray-300">{`// Define your data model
const schema = {
  name: 'products',
  fields: {
    title: { type: 'string', required: true },
    price: { type: 'number' },
    inStock: { type: 'boolean', default: true },
    category: { type: 'reference', table: 'categories' }
  }
}`}</pre>
          </div>
          <div className="overflow-hidden rounded-2xl bg-white/5 ring-1 ring-emerald-500/30">
            <div className="flex items-center gap-3 border-b border-emerald-500/20 bg-emerald-500/10 px-4 py-3">
              <span className="size-2 rounded-full bg-emerald-400" />
              <span className="text-xs font-medium text-emerald-300">
                2 · Auto-generated REST API — zero boilerplate
              </span>
            </div>
            <pre className="m-0 overflow-x-auto p-6 text-sm leading-relaxed text-gray-300">{`GET    /api/products
GET    /api/products/:id
POST   /api/products
PUT    /api/products/:id
DELETE /api/products/:id

// Filtering, sorting, pagination built in
GET /api/products?category=electronics&sort=-price&limit=20`}</pre>
          </div>
        </div>
        <p className="mt-8 text-center text-sm text-gray-400">
          3 ·{' '}
          <span className="font-mono text-gray-300">npm run deploy</span> — live in 300+ cities in
          under a minute.
        </p>
      </div>

      {/* ── Feature grid ── */}
      <div className="mx-auto mt-24 max-w-7xl px-6 sm:mt-40 lg:px-8">
        <SectionHeader
          eyebrow="Batteries included"
          title="Lightweight core. Powerful plugins."
          lede="Everything ships free and MIT — start with a lean runtime and enable exactly what you need."
        />
        <div className="mx-auto mt-16 grid max-w-2xl grid-cols-1 gap-8 sm:grid-cols-2 lg:max-w-none lg:grid-cols-3">
          {[
            {
              href: '/plugins',
              icon: ICONS.puzzle,
              title: 'Plugin Architecture',
              desc: (
                <>
                  25+ core plugins included. Build your own with the{' '}
                  <code className="text-xs text-gray-300">definePlugin()</code> SDK.
                </>
              ),
            },
            {
              href: '/plugins/ai-search',
              icon: ICONS.magnifier,
              title: 'AI Search',
              desc: 'RAG-powered semantic search with Cloudflare Vectorize. Natural language queries out of the box.',
            },
            {
              href: '/forms',
              icon: ICONS.pencil,
              title: 'Form Builder',
              desc: 'Drag-and-drop form builder with Turnstile bot protection and Google Maps integration.',
            },
            {
              href: '/authentication',
              icon: ICONS.fingerprint,
              title: 'Flexible Auth',
              desc: 'Password, OTP, and Magic Link authentication. Role-based access control built-in.',
            },
            {
              href: '/caching',
              icon: ICONS.bolt,
              title: 'Three-Tier Cache',
              desc: 'Memory → KV → D1 caching. 50-100x faster queries. Automatic invalidation.',
            },
            {
              href: '/plugins/workflow',
              icon: ICONS.arrowPath,
              title: 'Content Workflow',
              desc: 'Draft → Review → Published workflow. Version history with one-click restore.',
            },
          ].map((card) => (
            <Link
              key={card.href}
              href={card.href}
              className="group flex flex-col rounded-2xl bg-white/5 p-8 ring-1 ring-white/10 transition hover:bg-white/10 hover:ring-white/20 no-underline"
            >
              <div className="mb-6 flex size-10 items-center justify-center rounded-lg bg-cyan-500">
                <FeatureIcon d={card.icon} />
              </div>
              <h3 className="text-base/7 font-semibold text-white">{card.title}</h3>
              <div className="mt-1 flex-auto text-sm/6 text-gray-400">{card.desc}</div>
              <p className="mt-6 text-sm/6 font-semibold text-cyan-400 group-hover:text-cyan-300">
                Learn more <span aria-hidden="true">→</span>
              </p>
            </Link>
          ))}
        </div>
        <div className="mt-12 flex justify-center">
          <Link
            href="/plugins"
            className="rounded-md px-3.5 py-2.5 text-sm font-semibold text-white ring-1 ring-inset ring-white/10 hover:bg-white/5 no-underline"
          >
            See all plugins <span aria-hidden="true">→</span>
          </Link>
        </div>
      </div>

      {/* ── Pricing reality ── */}
      <div className="mx-auto mt-24 max-w-7xl px-6 sm:mt-40 lg:px-8">
        <SectionHeader
          eyebrow="Pricing"
          title="Stop overpaying for your CMS"
          lede="Rivals bill you monthly for their cloud. SonicJS isn't a hosting service — you deploy it to your own Cloudflare account (or your own server) and we never see a dollar. All features, no seats, no gates."
        />
        <div className="mx-auto mt-16 grid max-w-2xl grid-cols-1 gap-8 md:grid-cols-2 lg:max-w-none lg:grid-cols-4">
          {[
            {
              name: 'Strapi Cloud',
              price: '$99',
              period: '/mo',
              items: ['3 roles limit', 'Preview requires paid', 'Single region'],
            },
            {
              name: 'Payload Cloud',
              price: '$35',
              period: '+/mo',
              items: ['13GB RAM dev server', '4s query times', 'Single region'],
            },
            {
              name: 'Contentful',
              price: '$300',
              period: '+/mo',
              items: ['Usage-based billing', 'Content type limits', '$60k/yr enterprise'],
            },
          ].map((plan) => (
            <div key={plan.name} className="rounded-2xl bg-white/5 p-8 ring-1 ring-white/10">
              <div className="mb-6 text-center">
                <div className="mb-1 text-base/7 font-semibold text-gray-400">{plan.name}</div>
                <div className="text-4xl font-semibold tracking-tight text-white">
                  {plan.price}
                  <span className="text-base font-normal text-gray-500">{plan.period}</span>
                </div>
              </div>
              <ul className="m-0 list-none space-y-3 p-0 text-sm/6 text-gray-400">
                {plan.items.map((item) => (
                  <li key={item} className="flex items-center gap-3">
                    <span aria-hidden="true" className="text-red-400">
                      ✗
                    </span>
                    <span className="sr-only">Limitation:</span> {item}
                  </li>
                ))}
              </ul>
            </div>
          ))}
          <div className="relative rounded-2xl bg-cyan-500/10 p-8 ring-2 ring-cyan-500">
            <div className="absolute -top-3 left-1/2 -translate-x-1/2 whitespace-nowrap rounded-full bg-cyan-500 px-3 py-1 text-xs font-semibold text-white">
              RECOMMENDED
            </div>
            <div className="mb-6 text-center">
              <div className="mb-1 text-base/7 font-semibold text-cyan-400">
                SonicJS on your Cloudflare account
              </div>
              <div className="text-4xl font-semibold tracking-tight text-white">
                $0-5<span className="text-base font-normal text-gray-500">/mo</span>
              </div>
            </div>
            <ul className="m-0 list-none space-y-3 p-0 text-sm/6 text-gray-300">
              <li className="flex items-center gap-3">
                <span aria-hidden="true" className="text-emerald-400">
                  ✓
                </span>
                <span className="sr-only">Included:</span>100k req/day free
              </li>
              <li className="flex items-center gap-3">
                <span aria-hidden="true" className="text-emerald-400">
                  ✓
                </span>
                <span className="sr-only">Included:</span>All features included
              </li>
              <li className="flex items-center gap-3">
                <span aria-hidden="true" className="text-emerald-400">
                  ✓
                </span>
                <span className="sr-only">Included:</span>300+ edge locations
              </li>
            </ul>
          </div>
        </div>
        <p className="mt-6 text-center text-xs text-gray-500">
          SonicJS is software, not a hosting service — there&apos;s no SonicJS cloud and no bill
          from us, ever. $0–5/mo is what Cloudflare charges for your own account at typical
          traffic; self-hosting on Docker costs exactly $0 plus your hardware.
        </p>
      </div>

      {/* ── Deploy anywhere ── */}
      <div className="mx-auto mt-24 max-w-7xl px-6 sm:mt-40 lg:px-8">
        <SectionHeader
          eyebrow="No lock-in"
          title="Born on the edge. Runs anywhere."
          lede="Cloudflare is the flagship — edge-native, zero cold start, the fastest path. But you're never locked in. Same code, your infrastructure, no rewrite."
        />
        <div className="mx-auto mt-16 grid max-w-2xl grid-cols-1 gap-8 lg:max-w-none lg:grid-cols-3">
          <div className="relative rounded-2xl bg-cyan-500/10 p-8 ring-2 ring-cyan-500">
            <div className="absolute -top-3 left-8 rounded-full bg-cyan-500 px-3 py-1 text-xs font-semibold text-white">
              RECOMMENDED
            </div>
            <div className="mb-6 flex size-10 items-center justify-center rounded-lg bg-cyan-500">
              <FeatureIcon d="M2.25 15a4.5 4.5 0 0 0 4.5 4.5H18a3.75 3.75 0 0 0 1.332-7.257 3 3 0 0 0-3.758-3.848 5.25 5.25 0 0 0-10.233 2.33A4.502 4.502 0 0 0 2.25 15Z" />
            </div>
            <h3 className="text-base/7 font-semibold text-white">Cloudflare Workers</h3>
            <p className="mt-1 text-sm/6 text-gray-400">
              Edge-native, zero cold start, 300+ cities. D1 + R2 + KV. The fastest way to run
              SonicJS — and the default.
            </p>
          </div>
          <div className="rounded-2xl bg-white/5 p-8 ring-1 ring-white/10 lg:col-span-2">
            <h3 className="mb-6 text-base/7 font-semibold text-white">Also runs on</h3>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
              {[
                { label: 'Docker', desc: <code className="font-mono">docker run sonicjs</code> },
                { label: 'Any VPS', desc: 'DigitalOcean, Hetzner, Vultr' },
                { label: 'PaaS', desc: 'Railway, Render, Fly.io' },
                { label: 'Homelab', desc: 'Raspberry Pi, NAS, Unraid' },
                { label: 'On-prem', desc: 'Air-gapped & sovereign' },
                { label: 'Serverless', desc: 'Vercel, Netlify, Lambda' },
              ].map((target) => (
                <div key={target.label} className="rounded-lg bg-gray-800/60 p-4">
                  <div className="text-sm font-semibold text-white">{target.label}</div>
                  <div className="mt-0.5 text-xs text-gray-400">{target.desc}</div>
                </div>
              ))}
            </div>
            <p className="mt-6 text-xs text-gray-500">
              Runs anywhere SQLite runs. Managed Postgres + S3 for large-scale deploys is on the
              roadmap.
            </p>
          </div>
        </div>
      </div>

      {/* ── Built in the open ── */}
      <div className="mx-auto mt-24 max-w-7xl px-6 sm:mt-40 lg:px-8">
        <SectionHeader
          eyebrow="Community"
          title="Built in the open"
          lede={
            <>
              No sales calls, no gated demos, no VC roadmap. Just an MIT-licensed codebase shipping
              in public — releases land weekly.{' '}
              <Link
                href="/changelog"
                className="font-semibold text-cyan-400 hover:text-cyan-300"
              >
                View the full changelog →
              </Link>
            </>
          }
        />
        <div className="mt-12 flex flex-wrap items-center justify-center gap-4">
          <Link
            href="https://github.com/lane711/sonicjs"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 rounded-full px-5 py-2 text-sm font-medium text-gray-300 ring-1 ring-white/10 transition hover:bg-white/5 hover:text-white no-underline"
          >
            <svg className="h-4 w-4 fill-current" viewBox="0 0 20 20" aria-hidden="true">
              <path
                fillRule="evenodd"
                clipRule="evenodd"
                d="M10 1.667c-4.605 0-8.334 3.823-8.334 8.544 0 3.78 2.385 6.974 5.698 8.106.417.075.573-.182.573-.406 0-.203-.011-.875-.011-1.592-2.093.397-2.635-.522-2.802-1.002-.094-.246-.5-1.005-.854-1.207-.291-.16-.708-.556-.01-.567.656-.01 1.124.62 1.281.876.75 1.292 1.948.93 2.427.705.073-.555.291-.93.531-1.143-1.854-.213-3.791-.95-3.791-4.218 0-.929.322-1.698.854-2.296-.083-.214-.375-1.09.083-2.265 0 0 .698-.224 2.292.876a7.576 7.576 0 0 1 2.083-.288c.709 0 1.417.096 2.084.288 1.593-1.11 2.291-.875 2.291-.875.459 1.174.167 2.05.084 2.263.53.599.854 1.357.854 2.297 0 3.278-1.948 4.005-3.802 4.219.302.266.563.78.563 1.58 0 1.143-.011 2.061-.011 2.35 0 .224.156.491.573.405a8.365 8.365 0 0 0 4.11-3.116 8.707 8.707 0 0 0 1.567-4.99c0-4.721-3.73-8.545-8.334-8.545Z"
              />
            </svg>
            Open Source · MIT License
          </Link>
          <Link
            href="https://discord.gg/8bMy6bv3sZ"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 rounded-full px-5 py-2 text-sm font-medium text-gray-300 ring-1 ring-white/10 transition hover:bg-white/5 hover:text-white no-underline"
          >
            Discord Community
          </Link>
          <span className="flex items-center gap-2 rounded-full px-5 py-2 text-sm font-medium text-gray-300 ring-1 ring-white/10">
            Built on Cloudflare Workers
          </span>
          <span className="flex items-center gap-2 rounded-full px-5 py-2 text-sm font-medium text-gray-300 ring-1 ring-white/10">
            TypeScript-first
          </span>
        </div>
      </div>

      {/* ── Final CTA ── */}
      <div className="relative isolate mt-24 overflow-hidden px-6 py-24 sm:mt-40 sm:py-32 lg:px-8">
        <GridBackdrop patternId="cta-grid-pattern" />
        <GlowBlob className="absolute inset-x-0 top-10 -z-10 flex transform-gpu justify-center overflow-hidden blur-3xl" />
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-balance text-4xl font-semibold tracking-tight text-white sm:text-5xl">
            Ready to go supersonic?
          </h2>
          <p className="mx-auto mt-6 max-w-xl text-pretty text-lg/8 text-gray-300">
            MIT licensed. No credit card. No paywalls. Your first global deploy is minutes away.
          </p>
          <CopyCommand
            command="npx create-sonicjs@latest my-app"
            className="mx-auto mt-8 max-w-md"
          />
          <div className="mt-10 flex items-center justify-center gap-x-6">
            <Link
              href="https://discord.gg/8bMy6bv3sZ"
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm/6 font-semibold text-white no-underline"
            >
              Join Discord <span aria-hidden="true">→</span>
            </Link>
          </div>
          <div className="mt-6">
            <Link
              href="/quickstart"
              className="inline-flex rounded-md bg-cyan-500 px-3.5 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-cyan-400 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-500 no-underline"
            >
              Quickstart
            </Link>
          </div>
        </div>
      </div>
    </div>
  )
}
