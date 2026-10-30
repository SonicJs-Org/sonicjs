/**
 * Migrates legacy v2 stats data (backup JSON) into the document model.
 *
 * Usage:
 *   node scripts/migrate-legacy-data.mjs --remote   (production D1)
 *   node scripts/migrate-legacy-data.mjs            (local D1)
 *
 * Reads from:
 *   ../.context/events-backup-all.json
 *   ../.context/installs-backup.json
 *
 * Note: created_at in backup is milliseconds (v2 legacy) — converted to seconds.
 */

import { execSync } from 'child_process'
import { readFileSync, writeFileSync, unlinkSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

const __dir = dirname(fileURLToPath(import.meta.url))
const contextDir = join(__dir, '../../../.context')
const statsDir = join(__dir, '..')

const isRemote = process.argv.includes('--remote')
const remoteFlag = isRemote ? '--env production --remote' : '--local'

function toSeconds(val) {
  if (!val) return Math.floor(Date.now() / 1000)
  const n = Number(val)
  if (!isNaN(n)) {
    // already numeric: >1e10 = ms, else seconds
    return n > 1e10 ? Math.floor(n / 1000) : Math.floor(n)
  }
  // ISO string
  return Math.floor(new Date(val).getTime() / 1000)
}

function escapeSql(str) {
  return String(str ?? '').replace(/'/g, "''")
}

function runSqlFile(path) {
  execSync(`npx wrangler d1 execute DB ${remoteFlag} --file "${path}"`, {
    cwd: statsDir,
    encoding: 'utf8',
    stdio: 'inherit',
  })
}

function buildInserts(rows, typeId) {
  const now = Math.floor(Date.now() / 1000)
  return rows.map(row => {
    const id = crypto.randomUUID()
    const createdAt = toSeconds(row.created_at)
    const data = escapeSql(row.data)
    const title = escapeSql(row.title ?? '')
    return `INSERT OR IGNORE INTO documents ` +
      `(id, root_id, type_id, type_version, version_number, is_current_draft, is_published, status, ` +
      `parent_root_id, title, sort_order, visible, tenant_id, locale, data, created_at, updated_at) VALUES ` +
      `('${id}','${id}','${typeId}',1,1,0,1,'published','','${title}',0,1,'default','default','${data}',${createdAt},${createdAt});`
  })
}

function runInChunks(statements, label, chunkSize = 90) {
  const total = statements.length
  let done = 0
  for (let i = 0; i < total; i += chunkSize) {
    const chunk = statements.slice(i, i + chunkSize)
    const tmpFile = join(contextDir, `_tmp_chunk.sql`)
    writeFileSync(tmpFile, chunk.join('\n'))
    runSqlFile(tmpFile)
    unlinkSync(tmpFile)
    done += chunk.length
    console.log(`  ${label}: ${done}/${total}`)
  }
}

console.log(`\nMigrating to ${isRemote ? 'REMOTE (production)' : 'LOCAL'} D1...\n`)

// Seed document types
const now = Math.floor(Date.now() / 1000)
const seedSql = join(contextDir, '_seed_types.sql')
writeFileSync(seedSql, `
INSERT OR IGNORE INTO document_types
  (id, name, display_name, description, schema, queryable_fields, settings, source, schema_version, is_system, is_active, is_auth, created_at, updated_at)
VALUES
  ('events','events','Events','Telemetry events from SonicJS installations','{}','[]','{}','code',1,0,1,0,${now},${now}),
  ('installs','installs','Installs','Anonymous installation records','{}','[]','{}','code',1,0,1,0,${now},${now});
`.trim())
runSqlFile(seedSql)
unlinkSync(seedSql)
console.log('Document types seeded.')

// Migrate events
const eventsOffset = parseInt(process.env.EVENTS_OFFSET ?? '0')
const events = JSON.parse(readFileSync(join(contextDir, 'events-backup-all.json'), 'utf8')).slice(eventsOffset)
console.log(`Migrating ${events.length} events (offset ${eventsOffset})...`)
runInChunks(buildInserts(events, 'events'), 'events')

// Migrate installs
const installsOffset = parseInt(process.env.INSTALLS_OFFSET ?? '0')
const installs = JSON.parse(readFileSync(join(contextDir, 'installs-backup.json'), 'utf8')).slice(installsOffset)
console.log(`Migrating ${installs.length} installs (offset ${installsOffset})...`)
runInChunks(buildInserts(installs, 'installs'), 'installs')

// Verify
console.log('\nVerifying...')
const result = execSync(
  `npx wrangler d1 execute DB ${remoteFlag} --json --command "SELECT type_id, COUNT(*) as n FROM documents GROUP BY type_id;"`,
  { cwd: statsDir, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
)
const rows = JSON.parse(result)[0]?.results ?? []
console.log('Documents by type:', rows)
console.log('\nDone.')
