import type { DepartmentRecord, RegionRecord, EmployeeRecord } from '../types'

// ── Departments ───────────────────────────────────────────────────────────────

export const MOCK_DEPARTMENTS: DepartmentRecord[] = [
  { id: 'dept-engineering', title: 'Engineering',  slug: 'engineering',  status: 'published', collectionId: 'departments', created_at: 1700000000000, updated_at: 1700000000000, data: { name: 'Engineering',  description: 'Builds and maintains the product',            icon: '🔧', color: '#3B82F6' } },
  { id: 'dept-product',     title: 'Product',      slug: 'product',      status: 'published', collectionId: 'departments', created_at: 1700000000000, updated_at: 1700000000000, data: { name: 'Product',      description: 'Drives product vision and roadmap',           icon: '📊', color: '#8B5CF6' } },
  { id: 'dept-design',      title: 'Design',       slug: 'design',       status: 'published', collectionId: 'departments', created_at: 1700000000000, updated_at: 1700000000000, data: { name: 'Design',       description: 'Shapes user experience and visual identity',  icon: '🎨', color: '#EC4899' } },
  { id: 'dept-marketing',   title: 'Marketing',    slug: 'marketing',    status: 'published', collectionId: 'departments', created_at: 1700000000000, updated_at: 1700000000000, data: { name: 'Marketing',    description: 'Grows brand awareness and demand',            icon: '📣', color: '#F59E0B' } },
  { id: 'dept-sales',       title: 'Sales',        slug: 'sales',        status: 'published', collectionId: 'departments', created_at: 1700000000000, updated_at: 1700000000000, data: { name: 'Sales',        description: 'Closes deals and grows revenue',              icon: '💼', color: '#10B981' } },
  { id: 'dept-hr',          title: 'HR',           slug: 'hr',           status: 'published', collectionId: 'departments', created_at: 1700000000000, updated_at: 1700000000000, data: { name: 'HR',           description: 'Grows and supports the team',                 icon: '🤝', color: '#06B6D4' } },
  { id: 'dept-finance',     title: 'Finance',      slug: 'finance',      status: 'published', collectionId: 'departments', created_at: 1700000000000, updated_at: 1700000000000, data: { name: 'Finance',      description: 'Manages financial health and planning',        icon: '💰', color: '#84CC16' } },
  { id: 'dept-legal',       title: 'Legal',        slug: 'legal',        status: 'published', collectionId: 'departments', created_at: 1700000000000, updated_at: 1700000000000, data: { name: 'Legal',        description: 'Protects the business and ensures compliance', icon: '⚖️', color: '#6366F1' } },
  { id: 'dept-operations',  title: 'Operations',   slug: 'operations',   status: 'published', collectionId: 'departments', created_at: 1700000000000, updated_at: 1700000000000, data: { name: 'Operations',   description: 'Keeps the business running smoothly',          icon: '⚙️', color: '#F97316' } },
]

// ── Regions ───────────────────────────────────────────────────────────────────

export const MOCK_REGIONS: RegionRecord[] = [
  { id: 'region-us-east',  title: 'US East Coast',   slug: 'us-east',  status: 'published', collectionId: 'regions', created_at: 1700000000000, updated_at: 1700000000000, data: { name: 'US-East',  display_name: 'US East Coast',   timezone: 'America/New_York',    flag_emoji: '🇺🇸' } },
  { id: 'region-us-west',  title: 'US West Coast',   slug: 'us-west',  status: 'published', collectionId: 'regions', created_at: 1700000000000, updated_at: 1700000000000, data: { name: 'US-West',  display_name: 'US West Coast',   timezone: 'America/Los_Angeles', flag_emoji: '🇺🇸' } },
  { id: 'region-eu-west',  title: 'Western Europe',  slug: 'eu-west',  status: 'published', collectionId: 'regions', created_at: 1700000000000, updated_at: 1700000000000, data: { name: 'EU-West',  display_name: 'Western Europe',  timezone: 'Europe/London',       flag_emoji: '🇪🇺' } },
  { id: 'region-eu-north', title: 'Northern Europe', slug: 'eu-north', status: 'published', collectionId: 'regions', created_at: 1700000000000, updated_at: 1700000000000, data: { name: 'EU-North', display_name: 'Northern Europe', timezone: 'Europe/Stockholm',    flag_emoji: '🇸🇪' } },
  { id: 'region-apac',     title: 'Asia Pacific',    slug: 'apac',     status: 'published', collectionId: 'regions', created_at: 1700000000000, updated_at: 1700000000000, data: { name: 'APAC',     display_name: 'Asia Pacific',    timezone: 'Asia/Singapore',      flag_emoji: '🌏' } },
  { id: 'region-latam',    title: 'Latin America',   slug: 'latam',    status: 'published', collectionId: 'regions', created_at: 1700000000000, updated_at: 1700000000000, data: { name: 'LATAM',    display_name: 'Latin America',   timezone: 'America/Sao_Paulo',   flag_emoji: '🌎' } },
]

// ── Employee generation ───────────────────────────────────────────────────────

const FIRST = [
  'Alex', 'Jordan', 'Morgan', 'Taylor', 'Casey', 'Riley', 'Avery', 'Drew', 'Blake', 'Cameron',
  'Quinn', 'Peyton', 'Skyler', 'Reese', 'Logan', 'Parker', 'Hayden', 'Sydney', 'Jamie', 'Devon',
  'Emma', 'Liam', 'Olivia', 'Noah', 'Ava', 'Elijah', 'Sophia', 'Lucas', 'Isabella', 'Mason',
  'Charlotte', 'Ethan', 'Amelia', 'Aiden', 'Mia', 'James', 'Harper', 'Sebastian', 'Evelyn', 'Michael',
  'Priya', 'Kai', 'Zara', 'Noa', 'Ravi', 'Sasha', 'Mika', 'Ling', 'Jin', 'Aria',
]

const LAST = [
  'Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis', 'Wilson', 'Moore',
  'Taylor', 'Anderson', 'Thomas', 'Jackson', 'White', 'Harris', 'Martin', 'Thompson', 'Young', 'Lewis',
  'Walker', 'Hall', 'Allen', 'King', 'Wright', 'Scott', 'Torres', 'Nguyen', 'Hill', 'Flores',
  'Green', 'Adams', 'Nelson', 'Baker', 'Carter', 'Mitchell', 'Perez', 'Roberts', 'Turner', 'Phillips',
  'Patel', 'Kumar', 'Chen', 'Zhang', 'Kim', 'Park', 'Nakamura', 'Santos', 'Silva', 'Müller',
]

const DEPT_IDS = MOCK_DEPARTMENTS.map(d => d.id)
const REGION_IDS = MOCK_REGIONS.map(r => r.id)

const TITLES_BY_DEPT_ID: Record<string, string[]> = {
  'dept-engineering':  ['Software Engineer', 'Senior Engineer', 'Staff Engineer', 'Engineering Manager', 'DevOps Engineer', 'Frontend Engineer', 'Platform Engineer'],
  'dept-product':      ['Product Manager', 'Senior PM', 'Director of Product', 'Product Analyst', 'Associate PM'],
  'dept-design':       ['UX Designer', 'Product Designer', 'Design Lead', 'Visual Designer', 'UX Researcher'],
  'dept-marketing':    ['Marketing Manager', 'Content Strategist', 'Growth Manager', 'Brand Designer', 'SEO Specialist'],
  'dept-sales':        ['Account Executive', 'Sales Manager', 'SDR', 'VP of Sales', 'Customer Success Manager'],
  'dept-hr':           ['HR Manager', 'Recruiter', 'People Ops', 'HR Business Partner', 'Talent Lead'],
  'dept-finance':      ['Finance Manager', 'Financial Analyst', 'Controller', 'CFO', 'Accountant'],
  'dept-legal':        ['Legal Counsel', 'General Counsel', 'Compliance Manager', 'Legal Ops'],
  'dept-operations':   ['Operations Manager', 'Chief of Staff', 'Program Manager', 'IT Manager', 'Facilities Manager'],
}

function seededRand(seed: number): () => number {
  let s = seed
  return () => {
    s = (s * 16807 + 0) % 2147483647
    return (s - 1) / 2147483646
  }
}

function generate(count: number): EmployeeRecord[] {
  const rand = seededRand(42)
  const pick = <T>(arr: T[]): T => arr[Math.floor(rand() * arr.length)]!
  const records: EmployeeRecord[] = []
  for (let i = 0; i < count; i++) {
    const deptId = pick(DEPT_IDS)
    const firstName = pick(FIRST)
    const lastName = pick(LAST)
    records.push({
      id: `emp-${i + 1}`,
      title: `${firstName} ${lastName}`,
      slug: `${firstName.toLowerCase()}-${lastName.toLowerCase()}-${i + 1}`,
      status: 'published',
      collectionId: 'employees',
      data: {
        first_name: firstName,
        last_name: lastName,
        department: deptId,
        job_title: pick(TITLES_BY_DEPT_ID[deptId] ?? ['Employee']),
        region: pick(REGION_IDS),
        email: `${firstName.toLowerCase()}.${lastName.toLowerCase()}${i + 1}@example.com`,
        phone: `+1-555-${String(i + 1).padStart(4, '0')}`,
        avatar_seed: `employee-${i + 1}-${firstName}`,
      },
      created_at: 1700000000000 + i * 86400000,
      updated_at: 1700000000000 + i * 86400000,
    })
  }
  return records
}

export const ALL_EMPLOYEES = generate(500)

// ── Edge/origin toggle ────────────────────────────────────────────────────────

let _edgeMode = true

export function toggleEdgeMode(v: boolean) {
  _edgeMode = v
}

// ── Mock fetch — handles /api/departments, /api/regions, /api/employees ────────

export function mockFetch(input: string | URL | Request, _init?: RequestInit): Promise<Response> {
  const rawUrl = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url
  const url = new URL(rawUrl)
  const params = url.searchParams
  const path = url.pathname  // e.g. "/api/departments"

  const delay = _edgeMode ? 8 + Math.random() * 30 : 110 + Math.random() * 180

  const respond = (body: unknown) =>
    new Promise<Response>(resolve =>
      setTimeout(() => {
        resolve(new Response(JSON.stringify(body), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            'sonicjs-source': _edgeMode ? 'edge-cache' : 'origin',
          },
        }))
      }, delay),
    )

  // GET /api/departments
  if (path.endsWith('/api/departments') || path.endsWith('/departments')) {
    return respond({ data: MOCK_DEPARTMENTS, meta: { count: MOCK_DEPARTMENTS.length } })
  }

  // GET /api/regions
  if (path.endsWith('/api/regions') || path.endsWith('/regions')) {
    return respond({ data: MOCK_REGIONS, meta: { count: MOCK_REGIONS.length } })
  }

  // GET /api/employees (default — filter by dept/region reference IDs)
  const limit = parseInt(params.get('limit') ?? '18')
  const offset = parseInt(params.get('offset') ?? '0')
  const deptFilter = params.get('where[department][equals]')
  const regionFilter = params.get('where[region][equals]')

  let employees = ALL_EMPLOYEES
  if (deptFilter) employees = employees.filter(e => e.data.department === deptFilter)
  if (regionFilter) employees = employees.filter(e => e.data.region === regionFilter)

  const page = employees.slice(offset, offset + limit)
  return respond({ data: page, meta: { count: page.length, timestamp: Date.now() } })
}
