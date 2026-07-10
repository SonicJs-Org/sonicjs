/**
 * Seed departments → regions → employees with proper cross-collection references.
 *
 * Usage:
 *   CMS_URL=http://localhost:8787 CMS_API_KEY=sk_... npx tsx src/scripts/seed-employees.ts
 *   CMS_URL=https://demo.sonicjs.com CMS_API_KEY=sk_... npx tsx src/scripts/seed-employees.ts --count 50000
 */

import { createClient } from '../../../packages/sdk/src/index'

const CMS_URL = process.env['CMS_URL']
const CMS_API_KEY = process.env['CMS_API_KEY']
const COUNT = parseInt(process.argv.find(a => a.startsWith('--count='))?.split('=')[1] ?? process.argv[process.argv.indexOf('--count') + 1] ?? '2000', 10)
const BATCH = parseInt(process.argv.find(a => a.startsWith('--batch='))?.split('=')[1] ?? '10', 10)

if (!CMS_URL || !CMS_API_KEY) {
  console.error('Usage: CMS_URL=<url> CMS_API_KEY=<sk_...> npx tsx seed-employees.ts [--count 2000] [--batch 10]')
  process.exit(1)
}

// ── Seed data ───────────────────────────────────────────────────────────────

const DEPARTMENTS_DATA = [
  { name: 'Engineering',  description: 'Builds and maintains the product',          icon: '🔧', color: '#3B82F6' },
  { name: 'Product',      description: 'Drives product vision and roadmap',         icon: '📊', color: '#8B5CF6' },
  { name: 'Design',       description: 'Shapes user experience and visual identity',icon: '🎨', color: '#EC4899' },
  { name: 'Marketing',    description: 'Grows brand awareness and demand',          icon: '📣', color: '#F59E0B' },
  { name: 'Sales',        description: 'Closes deals and grows revenue',            icon: '💼', color: '#10B981' },
  { name: 'HR',           description: 'Grows and supports the team',               icon: '🤝', color: '#06B6D4' },
  { name: 'Finance',      description: 'Manages financial health and planning',     icon: '💰', color: '#84CC16' },
  { name: 'Legal',        description: 'Protects the business and ensures compliance', icon: '⚖️', color: '#6366F1' },
  { name: 'Operations',   description: 'Keeps the business running smoothly',       icon: '⚙️', color: '#F97316' },
] as const

const REGIONS_DATA = [
  { name: 'US-East',  display_name: 'US East Coast',     timezone: 'America/New_York',    flag_emoji: '🇺🇸' },
  { name: 'US-West',  display_name: 'US West Coast',     timezone: 'America/Los_Angeles', flag_emoji: '🇺🇸' },
  { name: 'EU-West',  display_name: 'Western Europe',    timezone: 'Europe/London',       flag_emoji: '🇪🇺' },
  { name: 'EU-North', display_name: 'Northern Europe',   timezone: 'Europe/Stockholm',    flag_emoji: '🇸🇪' },
  { name: 'APAC',     display_name: 'Asia Pacific',      timezone: 'Asia/Singapore',      flag_emoji: '🌏' },
  { name: 'LATAM',    display_name: 'Latin America',     timezone: 'America/Sao_Paulo',   flag_emoji: '🌎' },
] as const

const FIRST = [
  'Alex', 'Jordan', 'Morgan', 'Taylor', 'Casey', 'Riley', 'Avery', 'Drew', 'Blake', 'Cameron',
  'Quinn', 'Peyton', 'Skyler', 'Reese', 'Logan', 'Parker', 'Hayden', 'Sydney', 'Jamie', 'Devon',
  'Emma', 'Liam', 'Olivia', 'Noah', 'Ava', 'Elijah', 'Sophia', 'Lucas', 'Isabella', 'Mason',
  'Charlotte', 'Ethan', 'Amelia', 'Aiden', 'Mia', 'James', 'Harper', 'Sebastian', 'Evelyn', 'Michael',
  'Priya', 'Kai', 'Zara', 'Noa', 'Ravi', 'Sasha', 'Mika', 'Ling', 'Jin', 'Aria',
  'Felix', 'Luna', 'Omar', 'Isla', 'Marco', 'Yuki', 'Diego', 'Freya', 'Kofi', 'Mei',
]

const LAST = [
  'Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis', 'Wilson', 'Moore',
  'Taylor', 'Anderson', 'Thomas', 'Jackson', 'White', 'Harris', 'Martin', 'Thompson', 'Young', 'Lewis',
  'Walker', 'Hall', 'Allen', 'King', 'Wright', 'Scott', 'Torres', 'Nguyen', 'Hill', 'Flores',
  'Green', 'Adams', 'Nelson', 'Baker', 'Carter', 'Mitchell', 'Perez', 'Roberts', 'Turner', 'Phillips',
  'Patel', 'Kumar', 'Chen', 'Zhang', 'Kim', 'Park', 'Nakamura', 'Santos', 'Silva', 'Müller',
  'Osei', 'Tanaka', 'Costa', 'Rossi', 'Dubois', 'Ahmed', 'Hassan', 'Johansson', 'Weber', 'Ferreira',
]

type DeptName = (typeof DEPARTMENTS_DATA)[number]['name']

const TITLES: Record<DeptName, string[]> = {
  Engineering:  ['Software Engineer', 'Senior Engineer', 'Staff Engineer', 'Engineering Manager', 'DevOps Engineer', 'Frontend Engineer', 'Platform Engineer', 'Security Engineer'],
  Product:      ['Product Manager', 'Senior PM', 'Director of Product', 'Product Analyst', 'Associate PM', 'Group PM'],
  Design:       ['UX Designer', 'Product Designer', 'Design Lead', 'Visual Designer', 'UX Researcher', 'Design Systems Engineer'],
  Marketing:    ['Marketing Manager', 'Content Strategist', 'Growth Manager', 'Brand Designer', 'SEO Specialist', 'Demand Gen Manager'],
  Sales:        ['Account Executive', 'Sales Manager', 'SDR', 'VP of Sales', 'Customer Success Manager', 'Enterprise AE'],
  HR:           ['HR Manager', 'Recruiter', 'People Ops', 'HR Business Partner', 'Talent Lead', 'Comp & Benefits Analyst'],
  Finance:      ['Finance Manager', 'Financial Analyst', 'Controller', 'CFO', 'Accountant', 'FP&A Analyst'],
  Legal:        ['Legal Counsel', 'General Counsel', 'Compliance Manager', 'Legal Ops', 'Privacy Counsel'],
  Operations:   ['Operations Manager', 'Chief of Staff', 'Program Manager', 'IT Manager', 'Facilities Manager', 'Ops Analyst'],
}

// ── PRNG ─────────────────────────────────────────────────────────────────────

function seededRand(seed: number) {
  let s = seed
  return () => {
    s = (s * 16807 + 0) % 2147483647
    return (s - 1) / 2147483646
  }
}

function pick<T>(arr: readonly T[], r: () => number): T {
  return arr[Math.floor(r() * arr.length)]!
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const sonic = createClient({ url: CMS_URL!, apiKey: CMS_API_KEY })
  const rand = seededRand(42)

  // 1. Seed departments (create or fetch existing)
  console.log('Seeding departments…')
  const deptIds: Record<string, string> = {}
  const existingDepts = await sonic.collection('departments').list({ limit: 50, status: 'published' })
  for (const rec of existingDepts.data as unknown as Array<{ id: string; data: { name: string } }>) {
    deptIds[rec.data.name] = rec.id
    console.log(`  (exists) ${rec.data.name} → ${rec.id}`)
  }
  for (const dept of DEPARTMENTS_DATA) {
    if (deptIds[dept.name]) continue
    const { data } = await sonic.collection('departments').create({
      title: dept.name,
      status: 'published',
      data: { name: dept.name, description: dept.description, icon: dept.icon, color: dept.color },
    })
    deptIds[dept.name] = data.id
    console.log(`  ✓ ${dept.icon} ${dept.name} → ${data.id}`)
  }

  // 2. Seed regions (create or fetch existing)
  console.log('\nSeeding regions…')
  const regionIds: Record<string, string> = {}
  const existingRegions = await sonic.collection('regions').list({ limit: 50, status: 'published' })
  for (const rec of existingRegions.data as unknown as Array<{ id: string; data: { name: string } }>) {
    regionIds[rec.data.name] = rec.id
    console.log(`  (exists) ${rec.data.name} → ${rec.id}`)
  }
  for (const region of REGIONS_DATA) {
    if (regionIds[region.name]) continue
    const { data } = await sonic.collection('regions').create({
      title: region.display_name,
      status: 'published',
      data: { name: region.name, display_name: region.display_name, timezone: region.timezone, flag_emoji: region.flag_emoji },
    })
    regionIds[region.name] = data.id
    console.log(`  ✓ ${region.flag_emoji} ${region.name} → ${data.id}`)
  }

  const deptNames = DEPARTMENTS_DATA.map(d => d.name)
  const regionNames = REGIONS_DATA.map(r => r.name)

  // 3. Seed employees with reference IDs
  console.log(`\nSeeding ${COUNT} employees (batch=${BATCH})…`)
  let created = 0
  const errors: string[] = []

  for (let i = 0; i < COUNT; i += BATCH) {
    const chunk = Math.min(BATCH, COUNT - i)
    const creates = Array.from({ length: chunk }, (_, j) => {
      const idx = i + j
      const deptName = pick(deptNames, rand) as DeptName
      const regionName = pick(regionNames, rand)
      const firstName = pick(FIRST, rand)
      const lastName = pick(LAST, rand)

      return sonic.collection('employees').create({
        title: `${firstName} ${lastName}`,
        status: 'published',
        data: {
          first_name: firstName,
          last_name: lastName,
          department: deptIds[deptName]!,   // reference ID → departments collection
          job_title: pick(TITLES[deptName], rand),
          region: regionIds[regionName]!,   // reference ID → regions collection
          email: `${firstName.toLowerCase()}.${lastName.toLowerCase()}${idx + 1}@example.com`,
          phone: `+1-555-${String(idx + 1).padStart(5, '0')}`,
          avatar_seed: `employee-${idx + 1}-${firstName}-${lastName}`,
        },
      })
    })

    const results = await Promise.allSettled(creates)
    const ok = results.filter(r => r.status === 'fulfilled').length
    const fail = results.filter(r => r.status === 'rejected')
    created += ok
    for (const f of fail) errors.push((f as PromiseRejectedResult).reason?.message ?? 'unknown')

    if ((i / BATCH) % 10 === 0 || i + chunk >= COUNT) {
      process.stdout.write(`\r  ${created}/${COUNT} created, ${errors.length} errors`)
    }
  }

  console.log(`\n\n✓ Seed complete.`)
  console.log(`  Departments: ${Object.keys(deptIds).length}`)
  console.log(`  Regions:     ${Object.keys(regionIds).length}`)
  console.log(`  Employees:   ${created}/${COUNT} (${errors.length} errors)`)

  if (errors.length > 0) {
    console.log('First 5 errors:', errors.slice(0, 5))
  }
}

main().catch(e => { console.error(e); process.exit(1) })
