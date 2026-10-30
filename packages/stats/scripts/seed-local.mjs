#!/usr/bin/env node
/**
 * Local-only seed: inserts admin user directly into the miniflare SQLite file.
 * No Cloudflare auth or getPlatformProxy required.
 *
 * Usage: node scripts/seed-local.mjs [path-to-sqlite]
 */

import { createRequire } from 'module'
import { createHash, randomBytes, pbkdf2Sync } from 'node:crypto'
import { readdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'

const require = createRequire(import.meta.url)
const Database = require('better-sqlite3')

// ── Locate SQLite file ──────────────────────────────────────────────────────

const scriptDir = new URL('.', import.meta.url).pathname
const appDir = join(scriptDir, '..')
const d1Dir = join(appDir, '.wrangler/state/v3/d1/miniflare-D1DatabaseObject')

let dbPath = process.argv[2]

if (!dbPath) {
  if (!existsSync(d1Dir)) {
    console.error('❌ No .wrangler/state/v3/d1 directory found.')
    console.error('   Run migrations first: echo "y" | npx wrangler d1 migrations apply <db-name> --local')
    process.exit(1)
  }
  const files = readdirSync(d1Dir).filter(f => f.endsWith('.sqlite'))
  if (files.length === 0) {
    console.error('❌ No SQLite file found in', d1Dir)
    process.exit(1)
  }
  dbPath = join(d1Dir, files[0])
}

console.log('📂 Using SQLite:', dbPath)

const db = new Database(dbPath)

// ── Password hashing (PBKDF2, matches seed-admin.ts) ───────────────────────

function hashPassword(password) {
  const iterations = 100000
  const salt = randomBytes(16)
  const hash = pbkdf2Sync(password, salt, iterations, 32, 'sha256')
  return `pbkdf2:${iterations}:${salt.toString('hex')}:${hash.toString('hex')}`
}

// ── Admin user ──────────────────────────────────────────────────────────────

const EMAIL = 'admin@sonicjs.com'
const PASSWORD = 'sonicjs!'

let userId
const existing = db.prepare('SELECT id FROM auth_user WHERE email = ?').get(EMAIL)

if (existing) {
  userId = existing.id
  console.log('✓ Admin user already exists')
} else {
  const now = Math.floor(Date.now() / 1000)
  userId = `admin-${Date.now()}-${randomBytes(4).toString('hex')}`
  const passwordHash = hashPassword(PASSWORD)

  db.prepare(`
    INSERT INTO auth_user (id, email, first_name, last_name, role, is_active, created_at, updated_at, name, email_verified)
    VALUES (?, ?, 'Admin', 'User', 'admin', 1, ?, ?, 'Admin User', 1)
  `).run(userId, EMAIL, now, now)

  db.prepare(`
    INSERT INTO auth_account (id, user_id, account_id, provider_id, password, created_at, updated_at)
    VALUES (?, ?, ?, 'credential', ?, ?, ?)
  `).run(randomBytes(16).toString('hex'), userId, userId, passwordHash, now, now)

  console.log('✓ Admin user created')
  console.log('  Email:', EMAIL)
  console.log('  Password:', PASSWORD)
  console.log('  Role: admin')
}

// ── RBAC bootstrap ──────────────────────────────────────────────────────────
// Bootstrap normally runs these via RbacService on first request, but seed
// must do it upfront so requireRbac('portal','access') passes on first login.

const now = Math.floor(Date.now() / 1000)

// Ensure document_types exist for rbac_role and rbac_user_roles
const rbacTypes = [
  { id: 'rbac_role', name: 'rbac_role', display_name: 'RBAC Role' },
  { id: 'rbac_verb', name: 'rbac_verb', display_name: 'RBAC Verb' },
  { id: 'rbac_user_roles', name: 'rbac_user_roles', display_name: 'RBAC User Roles' },
]
const upsertType = db.prepare(`
  INSERT INTO document_types (id, name, display_name, description, schema, queryable_fields, settings, source, is_system, is_auth, created_at, updated_at)
  VALUES (?, ?, ?, NULL, '{}', '[]', '{}', 'system', 1, 1, ?, ?)
  ON CONFLICT(id) DO NOTHING
`)
for (const t of rbacTypes) {
  upsertType.run(t.id, t.name, t.display_name, now, now)
}
console.log('✓ RBAC document_types ensured')

// Ensure role-admin document exists
const adminRoleId = `role-admin-seed`
const adminRoleData = JSON.stringify({
  name: 'admin',
  displayName: 'Administrator',
  description: 'Full access',
  isSystem: true,
  grants: [
    { resource: '*', verb: '*', scope: 'any' },
    { resource: 'portal', verb: 'access', scope: 'any' },
  ],
})
db.prepare(`
  INSERT INTO documents (id, root_id, type_id, type_version, version_number, is_current_draft, is_published,
    status, parent_root_id, slug, title, tenant_id, locale, translation_group_id, data, metadata,
    visible, sort_order, created_at, updated_at)
  VALUES (?, ?, 'rbac_role', 1, 1, 1, 0, 'draft', '', 'role-admin', 'Administrator', 'default', 'default', '', ?, '{}', 1, 0, ?, ?)
  ON CONFLICT(id) DO NOTHING
`).run(adminRoleId, adminRoleId, adminRoleData, now, now)
console.log('✓ role-admin document ensured')

// Ensure user-roles document for this admin user
const userRolesId = `rbac-user-roles-${userId}`
const userRolesData = JSON.stringify({ roleIds: ['role-admin'] })
db.prepare(`
  INSERT INTO documents (id, root_id, type_id, type_version, version_number, is_current_draft, is_published,
    status, parent_root_id, slug, title, tenant_id, locale, translation_group_id, data, metadata,
    visible, sort_order, created_at, updated_at)
  VALUES (?, ?, 'rbac_user_roles', 1, 1, 1, 0, 'draft', '', ?, 'User Roles', 'default', 'default', '', ?, '{}', 1, 0, ?, ?)
  ON CONFLICT(id) DO NOTHING
`).run(userRolesId, userRolesId, userId, userRolesData, now, now)
console.log('✓ RBAC user-role link ensured (admin → role-admin)')

// ── plugin document_type ────────────────────────────────────────────────────
// documents.type_id FK requires document_types row to exist first.
db.prepare(`
  INSERT INTO document_types (id, name, display_name, description, schema, queryable_fields, settings, source, is_system, is_auth, created_at, updated_at)
  VALUES ('plugin', 'plugin', 'Plugin', NULL, '{}', '[]', '{}', 'system', 1, 0, ?, ?)
  ON CONFLICT(id) DO NOTHING
`).run(now, now)
console.log('✓ plugin document_type ensured')

// ── stats-dashboard plugin document ─────────────────────────────────────────
// Ensures stats-dashboard appears as active in the plugin list UI.
// plugin-bootstrap would normally install this on first boot via PLUGIN_REGISTRY,
// but seeding it here avoids the chicken-and-egg (need DB + running server).

const pluginId = 'plugin-stats-dashboard-seed'
const pluginData = JSON.stringify({
  name: 'stats-dashboard',
  displayName: 'Stats Dashboard',
  description: 'Weekly installation funnel dashboard for stats.sonicjs.com.',
  version: '1.0.0',
  author: 'SonicJS Team',
  category: 'analytics',
  icon: '📊',
  status: 'active',
  isCore: false,
  settings: {},
  permissions: ['admin:access'],
  dependencies: [],
  downloadCount: 0,
  rating: 0,
})
db.prepare(`
  INSERT INTO documents (id, root_id, type_id, version_number, is_current_draft, is_published, status,
    parent_root_id, slug, title, tenant_id, locale, translation_group_id,
    data, metadata, created_at, updated_at)
  VALUES (?, ?, 'plugin', 1, 1, 1, 'published',
    '', 'stats-dashboard', 'Stats Dashboard', 'default', 'default', '',
    ?, '{}', ?, ?)
  ON CONFLICT(id) DO NOTHING
`).run(pluginId, pluginId, pluginData, now, now)
console.log('✓ stats-dashboard plugin document ensured (active)')

// ── events document_type ────────────────────────────────────────────────────
db.prepare(`
  INSERT INTO document_types (id, name, display_name, description, schema, queryable_fields, settings, source, is_system, is_auth, created_at, updated_at)
  VALUES ('events', 'events', 'Events', NULL, '{}', '[]', '{}', 'system', 0, 0, ?, ?)
  ON CONFLICT(id) DO NOTHING
`).run(now, now)
console.log('✓ events document_type ensured')

// ── test event data (13 weeks of install funnel) ────────────────────────────
// Realistic-looking weekly funnel: started > completed > failed
// Timestamps spaced one week apart, ending at seed time.

const WEEK_S = 7 * 24 * 60 * 60  // seconds per week

// [started, completed, failed] per week, oldest first
const weeklyFunnel = [
  [12,  8, 2],
  [18, 12, 3],
  [15, 10, 2],
  [22, 16, 4],
  [19, 14, 3],
  [25, 18, 4],
  [30, 22, 5],
  [27, 20, 4],
  [35, 26, 6],
  [32, 24, 5],
  [40, 30, 7],
  [38, 29, 6],
  [45, 34, 8],
]

const insertEvent = db.prepare(`
  INSERT INTO documents (id, root_id, type_id, version_number, is_current_draft, is_published, status,
    parent_root_id, slug, title, tenant_id, locale, translation_group_id,
    data, metadata, created_at, updated_at)
  VALUES (?, ?, 'events', 1, 1, 1, 'published',
    '', ?, 'event', 'default', 'default', '',
    ?, '{}', ?, ?)
  ON CONFLICT(id) DO NOTHING
`)

let eventCount = 0
const weeksAgo = weeklyFunnel.length

for (let w = 0; w < weeklyFunnel.length; w++) {
  const [started, completed, failed] = weeklyFunnel[w]
  // Offset: oldest week first, most recent is ~current week
  const weekOffset = (weeksAgo - 1 - w) * WEEK_S
  const weekBase = now - weekOffset

  // Generate unique install IDs for this week's starters
  const installIds = Array.from({ length: started }, (_, i) =>
    `install-seed-w${w}-${i}-${randomBytes(4).toString('hex')}`
  )

  // installation_started events
  for (let i = 0; i < started; i++) {
    const id = `evt-seed-started-w${w}-${i}`
    const ts = weekBase + i * 600  // spread 10 min apart
    const data = JSON.stringify({ installation_id: installIds[i], event_type: 'installation_started', timestamp: new Date(ts * 1000).toISOString() })
    insertEvent.run(id, id, id, data, ts, ts)
    eventCount++
  }

  // installation_completed events (subset of starters)
  for (let i = 0; i < completed; i++) {
    const id = `evt-seed-completed-w${w}-${i}`
    const ts = weekBase + i * 600 + 1800  // 30 min after start
    const data = JSON.stringify({ installation_id: installIds[i], event_type: 'installation_completed', timestamp: new Date(ts * 1000).toISOString() })
    insertEvent.run(id, id, id, data, ts, ts)
    eventCount++
  }

  // installation_failed events (different install IDs — ones that didn't complete)
  for (let i = 0; i < failed; i++) {
    const failIdx = started - 1 - i  // use last starters as the failed ones
    const id = `evt-seed-failed-w${w}-${i}`
    const ts = weekBase + failIdx * 600 + 900  // 15 min after start
    const data = JSON.stringify({ installation_id: installIds[failIdx], event_type: 'installation_failed', timestamp: new Date(ts * 1000).toISOString() })
    insertEvent.run(id, id, id, data, ts, ts)
    eventCount++
  }
}

console.log(`✓ ${eventCount} test events seeded (13 weeks of install funnel)`)

db.close()
console.log('✓ Seed complete')
