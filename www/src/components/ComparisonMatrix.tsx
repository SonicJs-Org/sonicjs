import { Fragment } from 'react'
import clsx from 'clsx'

/**
 * Detailed feature-comparison matrix between SonicJS and other headless CMSs.
 *
 * Cell values are either a plain string (rendered as text) or one of the
 * sentinel marks below:
 *   yes            → built into core, no extra cost
 *   no             → not supported
 *   partial(note)  → limited / requires custom code / not first-class
 *   plugin(note)   → available via an official/bundled plugin or adapter
 *   paid(note)     → only in a paid / enterprise / cloud tier
 *   soon(note)     → on the SonicJS roadmap, not yet shipped
 *
 * This is intended as an honest, exhaustive inventory for evaluating gaps —
 * not a marketing piece. SonicJS is rated from its source/docs; competitors
 * from their official docs, GitHub, and pricing pages. Sanity and Contentful
 * are SaaS content platforms, so "self-hostable" rows are honestly No and many
 * features are plan-gated.
 *
 * Data last verified June 2026. Update LAST_VERIFIED when refreshed.
 */

const LAST_VERIFIED = 'June 2026'

type Mark = {
  kind: 'yes' | 'no' | 'partial' | 'plugin' | 'paid' | 'soon'
  note?: string
}
type Cell = string | Mark

const yes: Mark = { kind: 'yes' }
const no: Mark = { kind: 'no' }
const partial = (note?: string): Mark => ({ kind: 'partial', note })
const plugin = (note?: string): Mark => ({ kind: 'plugin', note })
const paid = (note?: string): Mark => ({ kind: 'paid', note })
const soon = (note?: string): Mark => ({ kind: 'soon', note })

// Column order — SonicJS first and visually highlighted.
const PRODUCTS = ['SonicJS', 'Payload', 'Strapi', 'Directus', 'Sanity', 'Contentful'] as const

interface Row {
  label: string
  // [SonicJS, Payload, Strapi, Directus, Sanity, Contentful]
  cells: [Cell, Cell, Cell, Cell, Cell, Cell]
}

interface Section {
  title: string
  rows: Row[]
}

const SECTIONS: Section[] = [
  {
    title: 'Architecture & Runtime',
    rows: [
      { label: 'Runtime', cells: ['Cloudflare Workers', 'Node.js', 'Node.js', 'Node.js', 'Hosted SaaS', 'Hosted SaaS'] },
      { label: 'Deployment model', cells: ['Global edge', 'Single-region', 'Single-region', 'Single-region', 'Managed SaaS', 'Managed SaaS'] },
      { label: 'Edge / serverless runtime', cells: [yes, partial('Vercel'), no, no, partial('CDN'), partial('CDN')] },
      { label: 'Database', cells: ['D1 (SQLite)', 'Postgres · Mongo', 'Postgres · MySQL', 'Postgres · +5', 'Content Lake', 'Proprietary'] },
      { label: 'Data layer / ORM', cells: ['Drizzle', 'Drizzle · Mongoose', 'Knex', 'Knex', 'GROQ', '—'] },
      { label: 'Typical cold start', cells: ['0–5 ms', '100–300 ms', '500–2000 ms', '300–1000 ms', 'n/a', 'n/a'] },
      { label: 'Global edge distribution', cells: [yes, no, no, no, yes, yes] },
      { label: 'Built-in caching', cells: ['3-tier', partial('Manual'), partial('Plugin'), partial('Cache'), 'API CDN', 'API CDN'] },
      { label: 'Auto-scaling', cells: [yes, partial('Infra'), partial('Infra'), partial('Infra'), yes, yes] },
      { label: 'Self-hostable anywhere', cells: [partial('CF only'), yes, yes, yes, no, no] },
      { label: 'Docker support', cells: [no, yes, yes, yes, no, no] },
      { label: 'Official managed cloud', cells: [no, paid('Paused'), paid(), paid(), yes, yes] },
    ],
  },
  {
    title: 'Pricing & Licensing',
    rows: [
      { label: 'License', cells: ['MIT', 'MIT', 'MIT (+ EE)', 'MSCL', 'MIT / SaaS', 'Proprietary'] },
      { label: 'Free to self-host', cells: [yes, yes, yes, partial('<$5M rev'), no, no] },
      { label: 'Free cloud tier', cells: [partial('CF free tier'), no, no, no, yes, yes] },
      { label: 'Paid cloud entry price', cells: ['Free / ~$5', '$35+/mo', '$15+/mo', '$25+/mo', '$15/seat', '~$300/mo'] },
      { label: 'Features behind paywall', cells: [no, no, paid('Several'), partial('Some'), paid('Several'), paid('Many')] },
    ],
  },
  {
    title: 'Content Modeling',
    rows: [
      { label: 'Collections / content types', cells: [yes, yes, yes, yes, yes, yes] },
      { label: 'Single types / globals', cells: [partial(), yes, yes, partial(), yes, partial()] },
      { label: 'Repeatable / array fields', cells: [yes, yes, yes, yes, yes, yes] },
      { label: 'Reusable component / group fields', cells: [yes, yes, yes, partial(), yes, partial()] },
      { label: 'Blocks / dynamic zones', cells: [yes, yes, yes, partial(), yes, yes] },
      { label: 'One-to-one relationships', cells: [partial(), yes, yes, yes, yes, yes] },
      { label: 'One-to-many relationships', cells: [yes, yes, yes, yes, yes, yes] },
      { label: 'Many-to-many relationships', cells: [partial(), yes, yes, yes, yes, yes] },
      { label: 'Polymorphic relationships', cells: [partial(), yes, partial(), yes, yes, yes] },
      { label: 'Conditional field logic', cells: [no, yes, yes, yes, yes, no] },
      { label: 'Field-level validation', cells: [yes, yes, yes, yes, yes, yes] },
      { label: 'Computed / virtual fields', cells: [no, partial(), partial(), partial(), partial(), no] },
      { label: 'Rich text editor', cells: ['TinyMCE', 'Lexical', 'CKEditor', 'TinyMCE', 'Portable Text', 'Rich Text'] },
      { label: 'Markdown field', cells: [yes, partial(), yes, yes, plugin(), yes] },
      { label: 'JSON field', cells: [yes, yes, yes, yes, partial(), yes] },
      { label: 'Custom field types', cells: [partial(), yes, yes, plugin(), yes, plugin()] },
      { label: 'UI / presentational fields', cells: [no, yes, partial(), yes, partial(), partial()] },
      { label: 'Field-level localization', cells: [soon(), yes, yes, yes, plugin(), yes] },
      { label: 'Built-in field types (approx.)', cells: ['~21', '~22', '~15', '~25', '~13', '~12'] },
    ],
  },
  {
    title: 'Content Management & Editorial',
    rows: [
      { label: 'Draft & publish', cells: [yes, yes, yes, yes, yes, yes] },
      { label: 'Version history / revisions', cells: [yes, yes, paid(), yes, partial('3-day free'), yes] },
      { label: 'Autosave', cells: [yes, yes, no, no, yes, yes] },
      { label: 'Scheduled publishing', cells: [yes, yes, paid(), partial('Flows'), paid(), paid()] },
      { label: 'Live preview', cells: [yes, yes, paid(), yes, yes, partial()] },
      { label: 'Editorial workflow / review stages', cells: [yes, partial(), paid(), partial(), partial(), paid()] },
      { label: 'Bulk edit / delete', cells: [yes, yes, yes, yes, partial(), yes] },
      { label: 'Document duplication', cells: [yes, yes, yes, yes, yes, yes] },
      { label: 'Soft delete / trash', cells: [no, yes, no, partial(), partial(), partial()] },
      { label: 'Concurrent edit locking', cells: [no, yes, partial(), partial(), yes, partial()] },
      { label: 'Editorial comments', cells: [no, no, no, yes, paid(), paid()] },
      { label: 'Real-time collaboration', cells: [no, no, no, no, yes, partial()] },
    ],
  },
  {
    title: 'APIs & Integration',
    rows: [
      { label: 'REST API', cells: [yes, yes, yes, yes, yes, yes] },
      { label: 'GraphQL API', cells: [soon(), yes, plugin(), yes, yes, yes] },
      { label: 'GraphQL subscriptions', cells: [no, no, no, yes, no, no] },
      { label: 'Realtime / WebSockets', cells: [soon(), no, no, yes, yes, no] },
      { label: 'Local / server-side API', cells: [yes, yes, yes, yes, no, no] },
      { label: 'Webhooks', cells: [yes, partial('Hooks'), yes, yes, yes, yes] },
      { label: 'Filtering / sorting / pagination', cells: [yes, yes, yes, yes, yes, yes] },
      { label: 'Deep relationship population', cells: [partial(), yes, yes, yes, yes, yes] },
      { label: 'Aggregation queries', cells: [no, partial(), no, yes, yes, no] },
      { label: 'Field selection / sparse fieldsets', cells: [yes, yes, yes, yes, yes, yes] },
      { label: 'Custom endpoints', cells: [yes, yes, yes, plugin(), partial(), plugin()] },
      { label: 'OpenAPI / Swagger spec', cells: [yes, plugin(), yes, yes, no, partial()] },
    ],
  },
  {
    title: 'Authentication & Authorization',
    rows: [
      { label: 'End-user / app auth', cells: [yes, yes, yes, yes, no, no] },
      { label: 'JWT / token auth', cells: [yes, yes, yes, yes, yes, yes] },
      { label: 'API keys / tokens', cells: [yes, yes, yes, yes, yes, yes] },
      { label: 'OAuth / social login', cells: [plugin(), partial(), yes, yes, yes, partial()] },
      { label: 'SSO / SAML', cells: [soon(), paid(), paid(), yes, paid(), paid()] },
      { label: 'Magic link', cells: [plugin(), no, no, no, yes, no] },
      { label: 'OTP / 2FA / MFA', cells: [plugin('OTP'), plugin(), no, yes, partial(), yes] },
      { label: 'Role-based access control', cells: [yes, yes, partial('Adv = EE'), yes, partial('2 free'), paid()] },
      { label: 'Collection-level permissions', cells: [yes, yes, yes, yes, paid(), paid()] },
      { label: 'Field-level permissions', cells: [yes, yes, paid(), yes, paid(), paid()] },
      { label: 'Document / row-level access', cells: [partial(), yes, partial(), yes, paid(), paid()] },
      { label: 'Custom access-control functions', cells: [no, yes, yes, partial(), paid(), no] },
      { label: 'Password reset', cells: [yes, yes, yes, yes, yes, yes] },
    ],
  },
  {
    title: 'Media & Assets',
    rows: [
      { label: 'Media library', cells: [yes, yes, yes, yes, yes, yes] },
      { label: 'Image resizing / transforms', cells: [yes, yes, yes, yes, yes, yes] },
      { label: 'Focal point', cells: [no, yes, yes, yes, yes, yes] },
      { label: 'Cloud storage adapters', cells: ['R2', yes, plugin(), yes, no, no] },
      { label: 'File metadata', cells: [yes, yes, yes, yes, yes, yes] },
      { label: 'Alt text / captions', cells: [yes, yes, yes, yes, partial(), partial()] },
      { label: 'Folders / organization', cells: [yes, yes, yes, yes, partial(), partial()] },
      { label: 'Image optimization', cells: [yes, partial(), yes, yes, yes, yes] },
      { label: 'CDN integration', cells: [yes, partial(), partial(), partial(), yes, yes] },
    ],
  },
  {
    title: 'Internationalization',
    rows: [
      { label: 'Content localization (i18n)', cells: [soon(), yes, yes, yes, plugin(), yes] },
      { label: 'Locale fallbacks', cells: [soon(), yes, no, partial(), plugin(), yes] },
      { label: 'Admin UI translations', cells: [no, yes, yes, yes, yes, partial()] },
      { label: 'RTL support', cells: [no, yes, partial(), yes, partial(), yes] },
    ],
  },
  {
    title: 'Admin Panel & UI',
    rows: [
      { label: 'Built-in admin UI', cells: ['HTMX', 'React / Next', 'React', 'Vue', 'React (Studio)', 'Web app'] },
      { label: 'Custom components / fields', cells: [partial(), yes, yes, plugin(), yes, plugin()] },
      { label: 'Customizable dashboard', cells: [yes, yes, partial(), yes, yes, plugin()] },
      { label: 'Custom admin views / routes', cells: [yes, yes, yes, plugin(), yes, plugin()] },
      { label: 'Theming / white-label', cells: [partial(), yes, partial(), partial(), partial(), paid()] },
      { label: 'Dark mode', cells: [yes, yes, yes, yes, yes, no] },
      { label: 'List view configuration', cells: [yes, yes, yes, yes, yes, yes] },
      { label: 'Conditional field display', cells: [no, yes, yes, yes, yes, no] },
    ],
  },
  {
    title: 'Extensibility & Automation',
    rows: [
      { label: 'Plugin / extension system', cells: [yes, yes, yes, yes, yes, yes] },
      { label: 'Lifecycle hooks', cells: [yes, yes, yes, yes, partial(), partial()] },
      { label: 'Middleware', cells: [yes, partial(), yes, partial(), partial(), no] },
      { label: 'Custom endpoints', cells: [yes, yes, yes, yes, partial(), plugin()] },
      { label: 'Cron / scheduled jobs', cells: [partial(), yes, yes, yes, partial(), partial()] },
      { label: 'Background jobs / queues', cells: [no, yes, no, partial(), no, no] },
      { label: 'Email sending', cells: [yes, yes, plugin(), yes, no, no] },
      { label: 'Visual automation builder', cells: [no, no, no, yes, no, paid()] },
      { label: 'Custom CLI', cells: [no, partial(), partial(), partial(), yes, yes] },
    ],
  },
  {
    title: 'Developer Experience',
    rows: [
      { label: 'TypeScript support', cells: [yes, yes, yes, yes, yes, yes] },
      { label: 'Schema as code', cells: [yes, yes, yes, yes, yes, yes] },
      { label: 'Type generation from schema', cells: [partial(), yes, yes, partial(), yes, plugin()] },
      { label: 'DB / content migrations', cells: [yes, yes, partial(), yes, yes, yes] },
      { label: 'Data seeding', cells: [yes, partial(), partial(), partial(), partial(), partial()] },
      { label: 'CLI scaffolding', cells: [yes, yes, yes, yes, yes, partial()] },
      { label: 'Official JS / TS SDK', cells: [no, yes, yes, yes, yes, yes] },
      { label: 'API playground / docs UI', cells: [yes, partial(), yes, partial(), yes, yes] },
    ],
  },
  {
    title: 'Security & Operations',
    rows: [
      { label: 'Rate limiting', cells: [yes, partial(), partial(), yes, yes, yes] },
      { label: 'CSRF protection', cells: [yes, yes, partial(), partial(), yes, partial()] },
      { label: 'CORS config', cells: [yes, yes, yes, yes, yes, yes] },
      { label: 'Audit logs', cells: [yes, partial(), paid(), yes, paid(), paid()] },
      { label: 'Field encryption', cells: [no, partial(), no, no, no, no] },
      { label: 'GDPR / data-export tools', cells: [partial(), partial(), partial(), yes, partial(), yes] },
      { label: 'Bot protection (CAPTCHA)', cells: [plugin('Turnstile'), no, no, no, partial(), partial()] },
      { label: 'Database transactions', cells: [yes, yes, yes, yes, yes, no] },
      { label: 'Multi-tenancy', cells: [partial(), plugin(), no, partial(), partial(), yes] },
    ],
  },
  {
    title: 'Ecosystem & Maturity',
    rows: [
      { label: 'First released', cells: ['2018', '2021', '2015', '2012', '2017', '2013'] },
      { label: 'GitHub stars (approx.)', cells: ['~1.6k', '~43k', '~72k', '~36k', '~6.2k', 'Closed'] },
      { label: 'Official plugins / marketplace', cells: ['~25 bundled', '~10 official', 'Marketplace', 'Marketplace', 'Marketplace', 'Marketplace'] },
      { label: 'Visual page builder', cells: [no, partial(), no, partial(), partial(), paid()] },
      { label: 'Built-in AI features', cells: [yes, no, paid(), no, partial(), paid()] },
    ],
  },
]

const MARK_STYLES: Record<Mark['kind'], { label: string; className: string } | null> = {
  yes: null,
  no: null,
  partial: { label: 'Partial', className: 'text-amber-600 dark:text-amber-400' },
  plugin: { label: 'Plugin', className: 'text-violet-600 dark:text-violet-400' },
  paid: { label: 'Paid', className: 'text-rose-600 dark:text-rose-400' },
  soon: { label: 'Roadmap', className: 'text-blue-600 dark:text-blue-400' },
}

function MarkCell({ mark }: { mark: Mark }) {
  if (mark.kind === 'yes') {
    return <span className="text-lg font-bold text-emerald-500 dark:text-emerald-400">✓</span>
  }
  if (mark.kind === 'no') {
    return <span className="text-lg text-gray-300 dark:text-gray-600">✗</span>
  }
  const style = MARK_STYLES[mark.kind]!
  return (
    <span className="inline-flex flex-col items-center leading-tight">
      <span className={clsx('text-xs font-semibold', style.className)}>{style.label}</span>
      {mark.note && <span className="text-[10px] text-gray-400 dark:text-gray-500">{mark.note}</span>}
    </span>
  )
}

function CellContent({ cell, highlight }: { cell: Cell; highlight: boolean }) {
  if (typeof cell === 'string') {
    return (
      <span
        className={clsx(
          'text-xs',
          highlight ? 'font-semibold text-blue-700 dark:text-blue-300' : 'text-gray-600 dark:text-gray-300',
        )}
      >
        {cell}
      </span>
    )
  }
  return <MarkCell mark={cell} />
}

function LegendItem({ swatch, label }: { swatch: React.ReactNode; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      {swatch}
      <span className="text-gray-600 dark:text-gray-400">{label}</span>
    </span>
  )
}

export function ComparisonMatrix() {
  return (
    <div className="not-prose my-10 w-full lg:!mx-0 lg:!max-w-none">
      <div className="mb-4 flex flex-wrap gap-x-5 gap-y-2 text-xs">
        <LegendItem swatch={<span className="font-bold text-emerald-500">✓</span>} label="Built-in" />
        <LegendItem swatch={<span className="text-gray-300 dark:text-gray-600">✗</span>} label="Not supported" />
        <LegendItem swatch={<span className="text-xs font-semibold text-amber-600 dark:text-amber-400">Partial</span>} label="Limited / custom code" />
        <LegendItem swatch={<span className="text-xs font-semibold text-violet-600 dark:text-violet-400">Plugin</span>} label="Via official plugin" />
        <LegendItem swatch={<span className="text-xs font-semibold text-rose-600 dark:text-rose-400">Paid</span>} label="Paid / enterprise tier" />
        <LegendItem swatch={<span className="text-xs font-semibold text-blue-600 dark:text-blue-400">Roadmap</span>} label="Planned, not shipped" />
      </div>
      <p className="mb-2 text-right text-xs text-gray-400 dark:text-gray-500 xl:hidden">
        6 products compared — scroll the table sideways to see Sanity &amp; Contentful →
      </p>
      <div className="overflow-x-auto rounded-xl border border-gray-200 dark:border-gray-800">
        <table className="w-full min-w-[920px] border-collapse text-left">
          <thead>
            <tr className="bg-gradient-to-r from-blue-50 to-purple-50 dark:from-blue-900/30 dark:to-purple-900/30">
              <th className="sticky left-0 z-10 bg-gradient-to-r from-blue-50 to-purple-50 px-2.5 py-2.5 text-sm font-bold text-gray-900 dark:from-blue-900/30 dark:to-purple-900/30 dark:text-white">
                Capability
              </th>
              {PRODUCTS.map((p, i) => (
                <th
                  key={p}
                  className={clsx(
                    'px-2.5 py-2.5 text-center text-sm font-bold',
                    i === 0
                      ? 'bg-blue-100/60 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300'
                      : 'text-gray-600 dark:text-gray-400',
                  )}
                >
                  {p}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {SECTIONS.map((section) => (
              <Fragment key={section.title}>
                <tr>
                  <th
                    colSpan={PRODUCTS.length + 1}
                    className="bg-gray-50 px-3 py-2 text-left text-xs font-bold uppercase tracking-wider text-gray-500 dark:bg-gray-800/60 dark:text-gray-400"
                  >
                    {section.title}
                  </th>
                </tr>
                {section.rows.map((row) => (
                  <tr
                    key={section.title + row.label}
                    className="border-t border-gray-100 hover:bg-gray-50/70 dark:border-gray-800 dark:hover:bg-gray-800/40"
                  >
                    <td className="sticky left-0 z-10 bg-white px-2.5 py-2.5 text-xs font-medium text-gray-900 dark:bg-gray-950 dark:text-white">
                      {row.label}
                    </td>
                    {row.cells.map((cell, i) => (
                      <td
                        key={i}
                        className={clsx('px-2.5 py-2.5 text-center align-middle', i === 0 && 'bg-blue-50/40 dark:bg-blue-900/10')}
                      >
                        <CellContent cell={cell} highlight={i === 0} />
                      </td>
                    ))}
                  </tr>
                ))}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-3 text-center text-xs text-gray-500 dark:text-gray-400">
        Data last verified {LAST_VERIFIED} against each project&rsquo;s official docs, GitHub, and pricing pages.
        Sanity and Contentful are hosted SaaS platforms, so &ldquo;self-hostable&rdquo; rows are No and several
        features are plan-gated. Corrections welcome via{' '}
        <a href="https://github.com/lane711/sonicjs" className="underline hover:text-gray-700 dark:hover:text-gray-300">
          GitHub
        </a>
        .
      </p>
    </div>
  )
}
