import { useState } from 'react'

// ── Reusable copy-able code block ─────────────────────────────────────────────

function CodeBlock({ label, lang, code }: { label: string; lang: string; code: string }) {
  const [copied, setCopied] = useState(false)

  const copy = async () => {
    await navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="bg-slate-900 border border-white/10 rounded-xl overflow-hidden text-sm">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-white/10">
        <span className="text-xs text-slate-400 font-medium">{label}</span>
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-600">{lang}</span>
          <button
            onClick={copy}
            className="text-xs text-slate-500 hover:text-white transition-colors px-2 py-0.5 rounded border border-white/10 hover:border-white/20"
          >
            {copied ? '✓ Copied' : 'Copy'}
          </button>
        </div>
      </div>
      <pre className="p-4 text-xs text-slate-300 overflow-x-auto leading-relaxed">
        <code>{code}</code>
      </pre>
    </div>
  )
}

// ── Section wrapper ───────────────────────────────────────────────────────────

function Section({ id, title, children }: { id: string; title: string; children: React.ReactNode }) {
  return (
    <section id={id} className="scroll-mt-20">
      <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
        <span className="w-1 h-5 bg-emerald-400 rounded-full inline-block" />
        {title}
      </h2>
      <div className="space-y-4">{children}</div>
    </section>
  )
}

// ── Schema table ──────────────────────────────────────────────────────────────

function SchemaTable({ fields }: { fields: { name: string; type: string; note?: string }[] }) {
  return (
    <div className="overflow-x-auto rounded-xl border border-white/10">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-white/10 bg-slate-900">
            <th className="text-left px-4 py-2.5 text-slate-400 font-medium w-1/3">Field</th>
            <th className="text-left px-4 py-2.5 text-slate-400 font-medium w-1/3">Type</th>
            <th className="text-left px-4 py-2.5 text-slate-400 font-medium">Notes</th>
          </tr>
        </thead>
        <tbody>
          {fields.map((f, i) => (
            <tr key={f.name} className={`border-b border-white/5 ${i % 2 === 0 ? 'bg-slate-950' : 'bg-slate-900/50'}`}>
              <td className="px-4 py-2.5 font-mono text-emerald-300">{f.name}</td>
              <td className="px-4 py-2.5 font-mono text-blue-300">{f.type}</td>
              <td className="px-4 py-2.5 text-slate-500">{f.note ?? ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ── Stat pill ─────────────────────────────────────────────────────────────────

function StatPill({ value, label }: { value: string; label: string }) {
  return (
    <div className="bg-slate-900 border border-white/10 rounded-xl p-4 text-center">
      <div className="text-2xl font-bold font-mono text-emerald-400">{value}</div>
      <div className="text-xs text-slate-500 mt-1">{label}</div>
    </div>
  )
}

// ── Main FAQ component ────────────────────────────────────────────────────────

export function FAQ() {
  const sonicCurlExample = `# Fetch first page of employees (10 per page)
curl 'https://speed-backend.sonicjs.com/api/employees?limit=10&offset=0&status=published' \\
  -H 'x-api-key: YOUR_API_KEY'

# Filter by department
curl 'https://speed-backend.sonicjs.com/api/employees?limit=10&offset=0&status=published&where%5Bdata.department%5D%5Bequals%5D=DEPT_ID' \\
  -H 'x-api-key: YOUR_API_KEY'

# Bypass edge cache (force origin)
curl 'https://speed-backend.sonicjs.com/api/employees?limit=10&offset=0&status=published' \\
  -H 'x-api-key: YOUR_API_KEY' \\
  -H 'Cache-Control: no-cache'`

  const sonicFetchExample = `import { createClient } from '@sonicjs-cms/sdk'

const sonic = createClient({
  url: 'https://speed-backend.sonicjs.com',
  apiKey: process.env.SONIC_API_KEY,
})

// Fetch a page of employees
const { data, meta, headers } = await sonic
  .collection('employees')
  .listWithHeaders({
    limit: 10,
    offset: 0,
    status: 'published',
    where: {
      'data.department': { equals: 'dept-engineering' },
    },
  })

console.log(\`\${data.length} employees (source: \${headers.get('x-cache-source')})\`)

// Fetch all departments
const { data: departments } = await sonic
  .collection('departments')
  .list({ limit: 50, status: 'published' })`

  const payloadCurlExample = `# Fetch first page (depth=1 auto-populates department + region objects)
curl 'https://payload.sonicjs.com/api/employees?limit=10&depth=1&page=1'

# Filter by department name
curl 'https://payload.sonicjs.com/api/employees?limit=10&depth=1&page=1&where[department.name][equals]=Engineering'

# Fetch all departments
curl 'https://payload.sonicjs.com/api/departments?limit=50'`

  const sonicResponseExample = `{
  "data": [
    {
      "id": "01JX...",
      "title": "Alex Johnson",
      "slug": "alex-johnson-1",
      "status": "published",
      "collectionId": "employees",
      "data": {
        "first_name": "Alex",
        "last_name": "Johnson",
        "department": "dept-engineering",   // ID → join against /departments
        "job_title": "Senior Engineer",
        "region": "region-us-east",         // ID → join against /regions
        "email": "alex.johnson1@example.com",
        "phone": "+1-555-0001",
        "avatar_seed": "employee-1-Alex"
      },
      "created_at": 1700000000000,
      "updated_at": 1700000000000
    }
    // ... 9 more
  ],
  "meta": {
    "count": 10,
    "timestamp": 1700000000000
  }
}`

  const payloadResponseExample = `{
  "docs": [
    {
      "id": 1,
      "firstName": "Alex",
      "lastName": "Johnson",
      "jobTitle": "Senior Engineer",
      "email": "alex.johnson@example.com",
      "phone": "+1-555-0001",
      "avatarSeed": "employee-1-Alex",
      "department": {               // depth=1: full object inlined
        "id": 1,
        "name": "Engineering",
        "icon": "🔧",
        "color": "#3B82F6"
      },
      "region": {                   // depth=1: full object inlined
        "id": 1,
        "name": "US East",
        "displayName": "US East Coast",
        "flagEmoji": "🇺🇸",
        "timezone": "America/New_York"
      }
    }
    // ... 9 more
  ],
  "totalDocs": 1000,
  "page": 1,
  "totalPages": 100,
  "hasNextPage": true
}`

  const sonicSchema = `// Every SonicJS content record shares this envelope
interface ContentRecord<T> {
  id:           string   // ULID
  title:        string
  slug:         string
  status:       'published' | 'draft'
  collectionId: string
  data:         T        // ← your fields live here
  created_at:   number   // Unix ms
  updated_at:   number
}

// Employee-specific data payload
interface EmployeeData {
  first_name:  string
  last_name:   string
  department:  string   // ID ref → departments collection
  job_title:   string
  region:      string   // ID ref → regions collection
  email:       string
  phone:       string
  avatar_seed: string   // used with robohash.org
}

type EmployeeRecord = ContentRecord<EmployeeData>`

  const payloadSchema = `// Payload returns resolved references at depth=1
interface PayloadEmployee {
  id:         number
  firstName:  string
  lastName:   string
  jobTitle:   string
  email:      string
  phone:      string
  avatarSeed: string
  department: {
    id:          number
    name:        string
    icon:        string
    color:       string
    description?: string
  }
  region: {
    id:          number
    name:        string
    displayName: string
    flagEmoji:   string
    timezone?:   string
  }
}`

  return (
    <div className="min-h-screen bg-slate-950 text-white">

      {/* Page hero */}
      <div className="border-b border-white/10 bg-slate-950/60 px-4 sm:px-6 lg:px-8 py-8">
        <div className="max-w-4xl mx-auto">
          <h1 className="text-2xl font-bold text-white mb-2">How This Demo Works</h1>
          <p className="text-slate-400 text-sm leading-relaxed max-w-2xl">
            A live employee directory racing two CMS backends — both on Cloudflare Workers + D1, but only SonicJS adds a KV edge cache.
            Everything below is real: the API calls, the schema, the data counts — and the source code is fully open so you can run this yourself.
          </p>
        </div>
      </div>

      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-14">

        {/* ── Dataset size ── */}
        <Section id="data" title="Dataset">
          <p className="text-sm text-slate-400">
            Both backends serve the same synthetic employee directory, seeded with identical counts.
            The comparison is apples-to-apples: same data, different architecture.
          </p>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <StatPill value="50,000" label="Employees" />
            <StatPill value="9" label="Departments" />
            <StatPill value="6" label="Regions" />
            <StatPill value="10" label="Records / page" />
          </div>
          <div className="bg-slate-900 border border-white/10 rounded-xl p-4 text-sm text-slate-400 leading-relaxed">
            <p className="font-semibold text-slate-300 mb-2">Departments</p>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5 text-xs">
              {[
                ['🔧','Engineering'], ['📊','Product'], ['🎨','Design'],
                ['📣','Marketing'], ['💼','Sales'], ['🤝','HR'],
                ['💰','Finance'], ['⚖️','Legal'], ['⚙️','Operations'],
              ].map(([icon, name]) => (
                <span key={name} className="text-slate-300">{icon} {name}</span>
              ))}
            </div>
            <p className="font-semibold text-slate-300 mt-3 mb-2">Regions</p>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5 text-xs">
              {[
                ['🇺🇸','US East Coast'], ['🇺🇸','US West Coast'], ['🇪🇺','Western Europe'],
                ['🇸🇪','Northern Europe'], ['🌏','Asia Pacific'], ['🌎','Latin America'],
              ].map(([flag, name]) => (
                <span key={name} className="text-slate-300">{flag} {name}</span>
              ))}
            </div>
          </div>
        </Section>

        {/* ── Architecture ── */}
        <Section id="architecture" title="Architecture">
          <div className="bg-slate-900/60 border border-white/5 rounded-xl p-4 text-xs text-slate-400 leading-relaxed">
            <p className="text-slate-300 font-medium mb-1.5">Why Payload?</p>
            <p>
              We chose Payload specifically because it also runs on <span className="text-white">Cloudflare Workers + D1</span> — the same underlying infrastructure as SonicJS.
              That makes this a true apples-to-apples comparison: same runtime, same database engine, same network.
            </p>
            <p className="mt-2">
              We could have compared against <span className="text-slate-300">Directus</span> or <span className="text-slate-300">Strapi</span> — and the speed gap would be even more dramatic —
              but those run on traditional Node.js servers with PostgreSQL or MySQL, so the difference in response time would partly reflect infrastructure, not just CMS architecture.
              Payload removes that variable entirely.
            </p>
            <p className="text-slate-300 font-medium mt-4 mb-1.5">Why so fast?</p>
            <p>
              SonicJS sits a KV cache in front of D1. The first request for any query hits the database and writes the result to Cloudflare KV — a globally distributed key-value store with sub-millisecond read latency at the edge.
              Every subsequent request for the same query is served directly from KV, never touching the database.
              Because KV is replicated to every Cloudflare data center, responses are served from the PoP closest to the user — typically under 30 ms anywhere in the world.
            </p>
            <a
              href="https://sonicjs.com/architecture#caching-strategy"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 mt-2 text-emerald-400 hover:text-emerald-300 transition-colors"
            >
              Read the full caching architecture ↗
            </a>
            <div className="mt-4 pt-4 border-t border-white/5">
              <p className="text-slate-300 font-medium mb-1.5">This is just the tip of the iceberg</p>
              <p>
                A single-user speed test shows the latency advantage, but the real benefit from edge caching shows up at scale.
                When thousands of requests hit the same query simultaneously, every one of them is served from KV in parallel with no database contention — 
                whereas an uncached backend serializes those hits against D1.
                The gap doesn't just hold under load, it widens.
              </p>
              <p className="mt-2">
                We're adding <span className="text-white">k6 load tests</span> that will drive sustained concurrent traffic at both backends and publish the full results — 
                throughput, p95/p99 latency, and error rates — along with all source code so you can reproduce the benchmark yourself.
              </p>
            </div>
          </div>
          <div className="grid sm:grid-cols-2 gap-4 text-sm">
            <div className="bg-slate-900 border border-emerald-500/20 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-3">
                <span className="text-emerald-400">⚡</span>
                <span className="font-semibold text-emerald-300">SonicJS Edge</span>
              </div>
              <ul className="space-y-1.5 text-slate-400 text-xs">
                <li className="flex gap-2"><span className="text-emerald-500 mt-0.5">→</span>Cloudflare Workers (zero cold starts)</li>
                <li className="flex gap-2"><span className="text-emerald-500 mt-0.5">→</span>D1 (SQLite at the edge) as source of truth</li>
                <li className="flex gap-2"><span className="text-emerald-500 mt-0.5">→</span>KV edge cache — responses served in &lt;30 ms globally</li>
                <li className="flex gap-2"><span className="text-emerald-500 mt-0.5">→</span><code className="text-emerald-300">x-cache-source</code> header tells you if it's cached</li>
                <li className="flex gap-2"><span className="text-emerald-500 mt-0.5">→</span>Send <code className="text-emerald-300">Cache-Control: no-cache</code> to bypass and hit DB</li>
              </ul>
            </div>
            <div className="bg-slate-900 border border-orange-500/20 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-3">
                <span className="text-orange-400">🐢</span>
                <span className="font-semibold text-orange-300">Payload CMS</span>
              </div>
              <ul className="space-y-1.5 text-slate-400 text-xs">
                <li className="flex gap-2"><span className="text-orange-500 mt-0.5">→</span>Cloudflare Workers (Paid plan — large bundle)</li>
                <li className="flex gap-2"><span className="text-orange-500 mt-0.5">→</span>D1 (SQLite at the edge) — same DB engine as SonicJS</li>
                <li className="flex gap-2"><span className="text-orange-500 mt-0.5">→</span>Next.js + Payload CMS via OpenNext adapter</li>
                <li className="flex gap-2"><span className="text-orange-500 mt-0.5">→</span>References auto-populated at <code className="text-orange-300">depth=1</code></li>
                <li className="flex gap-2"><span className="text-orange-500 mt-0.5">→</span>No edge caching — every request hits the DB</li>
              </ul>
            </div>
          </div>
        </Section>

        {/* ── SonicJS API ── */}
        <Section id="sonic-api" title="SonicJS API Calls">
          <p className="text-sm text-slate-400">
            The frontend uses <code className="text-emerald-300 bg-slate-900 px-1 rounded">@sonicjs-cms/sdk</code> (TypeScript-first wrapper), but the underlying REST API is plain HTTP — curl works fine.
          </p>
          <CodeBlock label="SDK (TypeScript)" lang="typescript" code={sonicFetchExample} />
          <CodeBlock label="Raw curl" lang="bash" code={sonicCurlExample} />
          <CodeBlock label="Example response" lang="json" code={sonicResponseExample} />
        </Section>

        {/* ── Payload API ── */}
        <Section id="payload-api" title="Payload CMS API Calls">
          <p className="text-sm text-slate-400">
            Payload exposes a standard REST API. The <code className="text-orange-300 bg-slate-900 px-1 rounded">depth=1</code> parameter tells it to populate related documents inline rather than returning raw IDs.
          </p>
          <CodeBlock label="Raw curl" lang="bash" code={payloadCurlExample} />
          <CodeBlock label="Example response (depth=1)" lang="json" code={payloadResponseExample} />
        </Section>

        {/* ── Schema ── */}
        <Section id="schema" title="Data Schema">
          <p className="text-sm text-slate-400 mb-2">
            SonicJS wraps every record in a <code className="text-emerald-300 bg-slate-900 px-1 rounded">ContentRecord&lt;T&gt;</code> envelope.
            References are stored as IDs — the client resolves them against the <code className="text-emerald-300 bg-slate-900 px-1 rounded">departments</code> and <code className="text-emerald-300 bg-slate-900 px-1 rounded">regions</code> collections.
            Payload resolves references server-side when <code className="text-orange-300 bg-slate-900 px-1 rounded">depth ≥ 1</code>.
          </p>

          <div className="space-y-6">
            <div>
              <p className="text-xs font-semibold text-emerald-400 uppercase tracking-wider mb-2">⚡ SonicJS — TypeScript types</p>
              <CodeBlock label="src/types.ts" lang="typescript" code={sonicSchema} />
            </div>

            <div>
              <p className="text-xs font-semibold text-slate-300 mb-2">SonicJS — Employee fields</p>
              <SchemaTable fields={[
                { name: 'id',           type: 'string (ULID)',   note: 'Unique record ID' },
                { name: 'title',        type: 'string',          note: 'Full display name' },
                { name: 'slug',         type: 'string',          note: 'URL-safe identifier' },
                { name: 'status',       type: '"published"|"draft"', note: '' },
                { name: 'collectionId', type: 'string',          note: '"employees"' },
                { name: 'data.first_name', type: 'string',       note: '' },
                { name: 'data.last_name',  type: 'string',       note: '' },
                { name: 'data.department', type: 'string (ID)',  note: 'Ref → departments collection' },
                { name: 'data.job_title',  type: 'string',       note: '' },
                { name: 'data.region',     type: 'string (ID)',  note: 'Ref → regions collection' },
                { name: 'data.email',      type: 'string',       note: '' },
                { name: 'data.avatar_seed','type': 'string',     note: 'Used with robohash.org' },
                { name: 'created_at',   type: 'number',          note: 'Unix milliseconds' },
                { name: 'updated_at',   type: 'number',          note: 'Unix milliseconds' },
              ]} />
            </div>

            <div>
              <p className="text-xs font-semibold text-orange-400 uppercase tracking-wider mb-2">🐢 Payload CMS — TypeScript types</p>
              <CodeBlock label="src/types.ts" lang="typescript" code={payloadSchema} />
            </div>
          </div>
        </Section>

        {/* ── Contact ── */}
        <Section id="contact" title="Questions?">
          <p className="text-sm text-slate-400">
            Reach the SonicJS team or community through any of these channels.
          </p>
          <div className="grid sm:grid-cols-3 gap-4">
            <a
              href="https://discord.gg/8bMy6bv3sZ"
              target="_blank"
              rel="noopener noreferrer"
              className="group bg-slate-900 border border-white/10 hover:border-indigo-500/40 rounded-xl p-4 transition-colors block"
            >
              <div className="text-xl mb-2">💬</div>
              <p className="font-semibold text-white text-sm group-hover:text-indigo-300 transition-colors mb-1">Discord</p>
              <p className="text-xs text-slate-500">Chat with the community, ask questions, share what you're building.</p>
            </a>

            <a
              href="https://github.com/SonicJs-Org/sonicjs/issues"
              target="_blank"
              rel="noopener noreferrer"
              className="group bg-slate-900 border border-white/10 hover:border-slate-400/40 rounded-xl p-4 transition-colors block"
            >
              <div className="text-xl mb-2">🐛</div>
              <p className="font-semibold text-white text-sm group-hover:text-slate-300 transition-colors mb-1">GitHub Issues</p>
              <p className="text-xs text-slate-500">Bug reports, feature requests, and technical questions.</p>
            </a>

            <a
              href="https://sonicjs.com/contact"
              target="_blank"
              rel="noopener noreferrer"
              className="group bg-slate-900 border border-white/10 hover:border-emerald-500/40 rounded-xl p-4 transition-colors block"
            >
              <div className="text-xl mb-2">✉️</div>
              <p className="font-semibold text-white text-sm group-hover:text-emerald-300 transition-colors mb-1">Contact</p>
              <p className="text-xs text-slate-500">Reach the team directly for business inquiries or support.</p>
            </a>
          </div>
        </Section>

        {/* ── Source links ── */}
        <Section id="repos" title="Source Code">

          {/* Live backend card */}
          <a
            href="https://speed-backend.sonicjs.com/admin"
            target="_blank"
            rel="noopener noreferrer"
            className="group bg-slate-900 border border-emerald-500/30 hover:border-emerald-400/60 rounded-xl p-5 transition-colors block mb-4"
          >
            <div className="flex items-center gap-3 mb-2">
              <div className="w-8 h-8 bg-emerald-500/20 border border-emerald-500/40 rounded-lg flex items-center justify-center flex-shrink-0">
                <span className="text-emerald-400 font-bold text-sm">⚡</span>
              </div>
              <span className="font-semibold text-white group-hover:text-emerald-300 transition-colors">Live SonicJS Admin</span>
              <span className="text-slate-600 text-xs ml-auto group-hover:text-emerald-500 transition-colors">↗</span>
            </div>
            <p className="text-xs text-slate-500 leading-relaxed mb-3">
              Browse the live backend powering this demo. Log in with the view-only account to explore collections, content, and settings.
            </p>
            <div className="bg-slate-800/60 rounded-lg px-3 py-2 text-xs font-mono space-y-1">
              <div className="flex gap-3">
                <span className="text-slate-500 w-16">URL</span>
                <span className="text-emerald-400">speed-backend.sonicjs.com/admin</span>
              </div>
              <div className="flex gap-3">
                <span className="text-slate-500 w-16">Email</span>
                <span className="text-slate-300">viewer@sonicjs.com</span>
              </div>
              <div className="flex gap-3">
                <span className="text-slate-500 w-16">Password</span>
                <span className="text-slate-300">sonicjs-view!</span>
              </div>
            </div>
          </a>

          <div className="grid sm:grid-cols-2 gap-4">
            <a
              href="https://github.com/SonicJs-Org/sonicjs"
              target="_blank"
              rel="noopener noreferrer"
              className="group bg-slate-900 border border-white/10 hover:border-emerald-500/40 rounded-xl p-5 transition-colors block"
            >
              <div className="flex items-center gap-3 mb-2">
                <div className="w-8 h-8 bg-emerald-400 rounded-lg flex items-center justify-center flex-shrink-0">
                  <span className="text-slate-900 font-bold text-sm">S</span>
                </div>
                <span className="font-semibold text-white group-hover:text-emerald-300 transition-colors">SonicJS</span>
                <span className="text-slate-600 text-xs ml-auto group-hover:text-emerald-500 transition-colors">↗</span>
              </div>
              <p className="text-xs text-slate-500 leading-relaxed">
                Edge-native headless CMS for Cloudflare Workers. TypeScript-first, D1 + KV, sub-100ms response times.
              </p>
              <p className="text-xs text-slate-700 mt-2 font-mono">github.com/SonicJs-Org/sonicjs</p>
            </a>

            <a
              href="https://github.com/SonicJs-Org/sonicjs-payload-demo"
              target="_blank"
              rel="noopener noreferrer"
              className="group bg-slate-900 border border-white/10 hover:border-orange-500/40 rounded-xl p-5 transition-colors block"
            >
              <div className="flex items-center gap-3 mb-2">
                <div className="w-8 h-8 bg-orange-400 rounded-lg flex items-center justify-center flex-shrink-0">
                  <span className="text-slate-900 font-bold text-sm">P</span>
                </div>
                <span className="font-semibold text-white group-hover:text-orange-300 transition-colors">Payload Demo</span>
                <span className="text-slate-600 text-xs ml-auto group-hover:text-orange-500 transition-colors">↗</span>
              </div>
              <p className="text-xs text-slate-500 leading-relaxed">
                Payload CMS backend used in this comparison. Node.js + PostgreSQL deployed on Cloudflare Workers.
              </p>
              <p className="text-xs text-slate-700 mt-2 font-mono">github.com/SonicJs-Org/sonicjs-payload-demo</p>
            </a>
          </div>

          <div className="bg-slate-900 border border-white/10 rounded-xl p-4 text-xs text-slate-500">
            <p className="text-slate-400 font-medium mb-1">This demo app</p>
            <p>
              Lives at <code className="text-slate-300">demos/speed-demo/</code> inside the main SonicJS repo.
              The TypeScript SDK it uses is at <code className="text-slate-300">packages/sdk/</code>.
            </p>
          </div>
        </Section>

        {/* ── Verify it yourself ── */}
        <Section id="diy" title="Verify It Yourself">
          <p className="text-sm text-slate-400 leading-relaxed">
            Everything you need to run this exact comparison on your own Cloudflare account is public and open source.
            Two repos, two Workers, one frontend — about 20 minutes start to finish.
          </p>

          {/* Prerequisites */}
          <div className="bg-slate-900 border border-white/10 rounded-xl p-4">
            <p className="font-semibold text-slate-300 mb-3 text-sm">Prerequisites</p>
            <ul className="space-y-1.5 text-xs text-slate-400">
              <li className="flex gap-2"><span className="text-emerald-500 mt-0.5">→</span><span>Cloudflare account — free tier works for SonicJS; <span className="text-orange-300">Payload requires the Paid Workers plan</span> (bundle &gt; 3 MB)</span></li>
              <li className="flex gap-2"><span className="text-emerald-500 mt-0.5">→</span>Node.js 18+ and <code className="text-slate-300">npm</code> / <code className="text-slate-300">pnpm</code></li>
              <li className="flex gap-2"><span className="text-emerald-500 mt-0.5">→</span>Wrangler CLI authenticated: <code className="text-slate-300">npx wrangler login</code></li>
            </ul>
          </div>

          {/* Step 1 — SonicJS */}
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <span className="w-6 h-6 rounded-full bg-emerald-400/20 border border-emerald-500/30 text-emerald-400 text-xs font-bold flex items-center justify-center flex-shrink-0">1</span>
              <p className="text-sm font-semibold text-white">Deploy the SonicJS backend</p>
            </div>
            <CodeBlock label="SonicJS — clone, create bindings, deploy, seed" lang="bash" code={`git clone https://github.com/SonicJs-Org/sonicjs
cd sonicjs
npm install

# Create the D1 database and KV namespace — copy the IDs printed to stdout
npx wrangler d1 create sonicjs-demo
npx wrangler kv namespace create CACHE_KV

# Paste the IDs into my-sonicjs-app/wrangler.client-backend.toml
# (replace database_id and the kv namespace id)

# Deploy the Worker
npx wrangler deploy --config my-sonicjs-app/wrangler.client-backend.toml

# Apply DB migrations then seed 50k employees
npx wrangler d1 migrations apply DB --remote --config my-sonicjs-app/wrangler.client-backend.toml
npx tsx my-sonicjs-app/scripts/seed-employees-demo.ts`} />
            <p className="text-xs text-slate-500">Your backend will be live at <code className="text-slate-400">https://&lt;worker-name&gt;.workers.dev</code>. Note this URL — you'll need it for the frontend.</p>
          </div>

          {/* Step 2 — Payload */}
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <span className="w-6 h-6 rounded-full bg-orange-400/20 border border-orange-500/30 text-orange-400 text-xs font-bold flex items-center justify-center flex-shrink-0">2</span>
              <p className="text-sm font-semibold text-white">Deploy the Payload backend <span className="text-orange-400 font-normal text-xs ml-1">(Paid Workers plan required)</span></p>
            </div>
            <CodeBlock label="Payload — clone, create bindings, deploy, seed" lang="bash" code={`git clone https://github.com/SonicJs-Org/sonicjs-payload-demo
cd sonicjs-payload-demo
pnpm install

# Create the D1 database and R2 bucket — copy the IDs
npx wrangler d1 create payload-sonicjs
npx wrangler r2 bucket create payload-sonicjs-media

# Paste the D1 database_id into wrangler.jsonc

# Set the required secret
npx wrangler secret put PAYLOAD_SECRET   # enter any random string

# Build and deploy (runs migrations automatically)
pnpm run deploy

# Seed 50k employees
npx tsx seed/generate.ts       # generates seed/employees-seed.json
npx tsx seed/seed-payload.ts`} />
            <p className="text-xs text-slate-500">Your Payload admin will be at <code className="text-slate-400">https://&lt;worker-name&gt;.workers.dev/admin</code>. Create an admin user on first visit.</p>
          </div>

          {/* Step 3 — Frontend */}
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <span className="w-6 h-6 rounded-full bg-blue-400/20 border border-blue-500/30 text-blue-400 text-xs font-bold flex items-center justify-center flex-shrink-0">3</span>
              <p className="text-sm font-semibold text-white">Run the speed-demo frontend</p>
            </div>
            <CodeBlock label="Frontend — point at your Workers and run" lang="bash" code={`# Already cloned in step 1 — from the sonicjs repo root
cd demos/speed-demo

# Point at your own Payload backend:
# Edit src/lib/payload-client.ts and replace the production URL:
#   'https://payload.sonicjs.com/api'  →  'https://<your-payload-worker>.workers.dev/api'

# Run locally against your own SonicJS backend
VITE_CMS_URL=https://<your-sonicjs-worker>.workers.dev npm run dev

# Or build and deploy to Cloudflare Pages
npm run build
npx wrangler pages deploy dist --project-name my-speed-demo`} />
          </div>

          {/* What to look for */}
          <div className="bg-slate-900 border border-emerald-500/20 rounded-xl p-4">
            <p className="font-semibold text-emerald-300 mb-2 text-sm">✓ What to look for</p>
            <ul className="space-y-1.5 text-xs text-slate-400">
              <li className="flex gap-2"><span className="text-emerald-500 mt-0.5">→</span>First SonicJS request hits origin (slower) — subsequent requests are served from KV cache (&lt;30 ms)</li>
              <li className="flex gap-2"><span className="text-emerald-500 mt-0.5">→</span>The <code className="text-slate-300">x-cache-source</code> response header shows <code className="text-emerald-300">edge-cache</code> vs <code className="text-slate-300">origin</code></li>
              <li className="flex gap-2"><span className="text-emerald-500 mt-0.5">→</span>Payload is consistent but slower — every request goes to D1 with no caching layer</li>
              <li className="flex gap-2"><span className="text-emerald-500 mt-0.5">→</span>Use the refresh button in the header to re-run the race and watch the timings</li>
            </ul>
          </div>
        </Section>

      </div>
    </div>
  )
}
