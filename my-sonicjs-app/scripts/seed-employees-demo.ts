/**
 * Seed departments, regions, and employees into the local demo D1.
 * Uses wrangler-demo.toml so it targets the same miniflare instance as dev:demo.
 * Idempotent: skips records whose slug already exists.
 *
 * Run via: npm run seed:employees:demo
 * Or automatically via: npm run setup:db:demo
 */
import { getPlatformProxy } from 'wrangler'
import { DocumentsService } from '../../packages/core/src/services/documents'
import { bootstrapDocumentTypes } from '../../packages/core/src/services/document-types-seed'

const TENANT = 'default'

// ── Static data ──────────────────────────────────────────────────────────────

const DEPARTMENTS = [
  { slug: 'engineering', name: 'Engineering',  description: 'Builds and maintains the product',             icon: '🔧', color: '#3B82F6' },
  { slug: 'product',     name: 'Product',      description: 'Drives product vision and roadmap',            icon: '📊', color: '#8B5CF6' },
  { slug: 'design',      name: 'Design',       description: 'Shapes user experience and visual identity',   icon: '🎨', color: '#EC4899' },
  { slug: 'marketing',   name: 'Marketing',    description: 'Grows brand awareness and demand',             icon: '📣', color: '#F59E0B' },
  { slug: 'sales',       name: 'Sales',        description: 'Closes deals and grows revenue',               icon: '💼', color: '#10B981' },
  { slug: 'hr',          name: 'HR',           description: 'Grows and supports the team',                  icon: '🤝', color: '#06B6D4' },
  { slug: 'finance',     name: 'Finance',      description: 'Manages financial health and planning',        icon: '💰', color: '#84CC16' },
  { slug: 'legal',       name: 'Legal',        description: 'Protects the business and ensures compliance', icon: '⚖️', color: '#6366F1' },
  { slug: 'operations',  name: 'Operations',   description: 'Keeps the business running smoothly',         icon: '⚙️', color: '#F97316' },
]

const REGIONS = [
  { slug: 'us-east',  name: 'US-East',  display_name: 'US East Coast',   timezone: 'America/New_York',    flag_emoji: '🇺🇸' },
  { slug: 'us-west',  name: 'US-West',  display_name: 'US West Coast',   timezone: 'America/Los_Angeles', flag_emoji: '🇺🇸' },
  { slug: 'eu-west',  name: 'EU-West',  display_name: 'Western Europe',  timezone: 'Europe/London',       flag_emoji: '🇪🇺' },
  { slug: 'eu-north', name: 'EU-North', display_name: 'Northern Europe', timezone: 'Europe/Stockholm',    flag_emoji: '🇸🇪' },
  { slug: 'apac',     name: 'APAC',     display_name: 'Asia Pacific',    timezone: 'Asia/Singapore',      flag_emoji: '🌏' },
  { slug: 'latam',    name: 'LATAM',    display_name: 'Latin America',   timezone: 'America/Sao_Paulo',   flag_emoji: '🌎' },
]

const TITLES_BY_DEPT: Record<string, string[]> = {
  engineering: ['Software Engineer', 'Senior Engineer', 'Staff Engineer', 'Engineering Manager', 'DevOps Engineer', 'Frontend Engineer', 'Platform Engineer'],
  product:     ['Product Manager', 'Senior PM', 'Director of Product', 'Product Analyst', 'Associate PM'],
  design:      ['UX Designer', 'Product Designer', 'Design Lead', 'Visual Designer', 'UX Researcher'],
  marketing:   ['Marketing Manager', 'Content Strategist', 'Growth Manager', 'Brand Designer', 'SEO Specialist'],
  sales:       ['Account Executive', 'Sales Manager', 'SDR', 'VP of Sales', 'Customer Success Manager'],
  hr:          ['HR Manager', 'Recruiter', 'People Ops', 'HR Business Partner', 'Talent Lead'],
  finance:     ['Finance Manager', 'Financial Analyst', 'Controller', 'CFO', 'Accountant'],
  legal:       ['Legal Counsel', 'General Counsel', 'Compliance Manager', 'Legal Ops'],
  operations:  ['Operations Manager', 'Chief of Staff', 'Program Manager', 'IT Manager', 'Facilities Manager'],
}

const FIRST = ['Alex','Jordan','Morgan','Taylor','Casey','Riley','Avery','Drew','Blake','Cameron','Quinn','Peyton','Skyler','Reese','Logan','Parker','Hayden','Sydney','Jamie','Devon','Emma','Liam','Olivia','Noah','Ava','Elijah','Sophia','Lucas','Isabella','Mason','Charlotte','Ethan','Amelia','Aiden','Mia','James','Harper','Sebastian','Evelyn','Michael','Priya','Kai','Zara','Noa','Ravi','Sasha','Mika','Ling','Jin','Aria']
const LAST  = ['Smith','Johnson','Williams','Brown','Jones','Garcia','Miller','Davis','Wilson','Moore','Taylor','Anderson','Thomas','Jackson','White','Harris','Martin','Thompson','Young','Lewis','Walker','Hall','Allen','King','Wright','Scott','Torres','Nguyen','Hill','Flores','Green','Adams','Nelson','Baker','Carter','Mitchell','Perez','Roberts','Turner','Phillips','Patel','Kumar','Chen','Zhang','Kim','Park','Nakamura','Santos','Silva','Müller']

function seededRand(seed: number) {
  let s = seed
  return () => { s = (s * 16807) % 2147483647; return (s - 1) / 2147483646 }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

async function slugExists(db: any, slug: string, typeId: string): Promise<boolean> {
  const row = await db.prepare(
    `SELECT 1 FROM documents WHERE slug=? AND type_id=? AND tenant_id=? AND is_current_draft=1 AND deleted_at IS NULL LIMIT 1`
  ).bind(slug, typeId, TENANT).first()
  return !!row
}

async function upsertDoc(svc: DocumentsService, typeId: string, slug: string, title: string, data: Record<string, unknown>, exists: boolean): Promise<string> {
  if (exists) return slug // already seeded
  const doc = await svc.create({ typeId, tenantId: TENANT, slug, data: { title, slug, status: 'published', ...data } })
  await svc.publish(doc.rootId, TENANT)
  return doc.rootId
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function seed() {
  const { env, dispose } = await getPlatformProxy({ configPath: './wrangler-demo.toml' })
  const db = (env as any).DB as D1Database
  if (!db) { console.error('❌ DB binding not found'); process.exit(1) }

  console.log('Bootstrapping document types...')
  await bootstrapDocumentTypes(db)

  // Insert collection document types via raw SQL — bypasses DocumentTypeRegistry
  // machinery which can silently fail in the wrangler proxy environment.
  const now = Math.floor(Date.now() / 1000)
  const defaultGrants = JSON.stringify({ admin: ['read','create','update','delete','publish','manage'], editor: ['read','create','update','publish'], viewer: ['read'], public: ['read'] })
  const emptySchema = JSON.stringify({ queryableFields: [], settings: {} })
  for (const [id, displayName, description] of [
    ['departments', 'Departments', 'Company departments — referenced by employees'],
    ['regions', 'Regions', 'Geographic regions — referenced by employees'],
    ['employees', 'Employees', 'Employee directory — powers the SonicJS SDK demo'],
  ] as [string, string, string][]) {
    await db.prepare(
      `INSERT OR IGNORE INTO document_types (id, name, display_name, description, schema, queryable_fields, settings, plugin_id, source, schema_version, is_system, is_active, is_auth, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, '[]', ?, NULL, 'system', 1, 0, 1, 0, ?, ?)`
    ).bind(id, id, displayName, description, emptySchema, JSON.stringify({ baseGrants: JSON.parse(defaultGrants), maxVersionsPerRoot: 50 }), now, now).run()
    console.log(`  ✓ document_type: ${id}`)
  }

  const svc = new DocumentsService(db)

  // ── Departments ───────────────────────────────────────────────────────────
  console.log('Seeding departments...')
  const deptIdBySlug: Record<string, string> = {}
  for (const d of DEPARTMENTS) {
    const exists = await slugExists(db, d.slug, 'departments')
    if (exists) {
      const row = await db.prepare(`SELECT root_id FROM documents WHERE slug=? AND type_id='departments' AND tenant_id=? AND is_current_draft=1 LIMIT 1`).bind(d.slug, TENANT).first() as any
      deptIdBySlug[d.slug] = row?.root_id ?? d.slug
      process.stdout.write('.')
    } else {
      const id = await upsertDoc(svc, 'departments', d.slug, d.name, d, false)
      deptIdBySlug[d.slug] = id
      process.stdout.write('+')
    }
  }
  console.log(` (${DEPARTMENTS.length} departments)`)

  // ── Regions ───────────────────────────────────────────────────────────────
  console.log('Seeding regions...')
  const regionIdBySlug: Record<string, string> = {}
  for (const r of REGIONS) {
    const exists = await slugExists(db, r.slug, 'regions')
    if (exists) {
      const row = await db.prepare(`SELECT root_id FROM documents WHERE slug=? AND type_id='regions' AND tenant_id=? AND is_current_draft=1 LIMIT 1`).bind(r.slug, TENANT).first() as any
      regionIdBySlug[r.slug] = row?.root_id ?? r.slug
      process.stdout.write('.')
    } else {
      const id = await upsertDoc(svc, 'regions', r.slug, r.display_name, r, false)
      regionIdBySlug[r.slug] = id
      process.stdout.write('+')
    }
  }
  console.log(` (${REGIONS.length} regions)`)

  // ── Employees ─────────────────────────────────────────────────────────────
  const DEPT_SLUGS = DEPARTMENTS.map(d => d.slug)
  const REGION_SLUGS = REGIONS.map(r => r.slug)
  const rand = seededRand(42)
  const pick = <T>(arr: T[]): T => arr[Math.floor(rand() * arr.length)]!

  const COUNT = 50 // enough for demo; remote has 500
  console.log(`Seeding ${COUNT} employees...`)
  let created = 0, skipped = 0
  for (let i = 0; i < COUNT; i++) {
    const deptSlug = pick(DEPT_SLUGS)
    const regionSlug = pick(REGION_SLUGS)
    const firstName = pick(FIRST)
    const lastName = pick(LAST)
    const slug = `${firstName.toLowerCase()}-${lastName.toLowerCase()}-${i + 1}`
    const exists = await slugExists(db, slug, 'employees')
    if (exists) { skipped++; process.stdout.write('.'); continue }
    await upsertDoc(svc, 'employees', slug, `${firstName} ${lastName}`, {
      first_name: firstName,
      last_name: lastName,
      department: deptIdBySlug[deptSlug],
      region: regionIdBySlug[regionSlug],
      job_title: pick(TITLES_BY_DEPT[deptSlug] ?? ['Employee']),
      email: `${firstName.toLowerCase()}.${lastName.toLowerCase()}${i + 1}@example.com`,
      phone: `+1-555-${String(i + 1).padStart(4, '0')}`,
      avatar_seed: `employee-${i + 1}-${firstName}-${lastName}`,
      status: 'published',
    }, false)
    created++
    process.stdout.write('+')
  }
  console.log(` (${created} created, ${skipped} skipped)`)

  await dispose()
  console.log('✓ Employee seed complete')
}

seed().then(() => process.exit(0)).catch(e => { console.error(e); process.exit(1) })
