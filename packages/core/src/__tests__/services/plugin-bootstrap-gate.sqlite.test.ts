// @ts-nocheck
// Real-SQLite coverage for the gate that decides whether core plugins get installed.
//
// `isBootstrapNeeded()` used to narrow its check to plugins whose name starts with `core-`,
// which left `lexical-editor` and `two-factor-auth` — both marked defaultActive, both in the
// bootstrap list — outside the gate entirely. Once `core-auth` and `core-media` were installed
// and active the gate answered "not needed" forever, so a boot that was cut off partway through
// the install loop could never be repaired: the two plugins stayed uninstalled, and every
// richtext field on the deployment silently fell back to a plain textarea.
//
// The end state is identical either way once everything is installed, so the only thing that
// pins the defect is asking the gate about a half-installed database. The mock suite cannot
// (R10) — it does not run the SQL.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../utils/d1-sqlite'
import { PluginBootstrapService } from '../../services/plugin-bootstrap'

const PLUGIN_TYPE_SQL = `
  INSERT INTO document_types (id, name, display_name, schema, queryable_fields, settings, source, schema_version, is_system, is_active, created_at, updated_at)
  VALUES ('plugin','plugin','Plugin','{}','[]','{}','system',1,1,1,1,1)
`

/** The four ids PluginBootstrapService installs: core-auth plus every defaultActive manifest. */
const BOOTSTRAPPED = ['core-auth', 'core-media', 'lexical-editor', 'two-factor-auth']

async function installPlugin(db, slug, status = 'active') {
  const data = JSON.stringify({ name: slug, status, isCore: slug.startsWith('core-') })
  await db
    .prepare(
      `INSERT INTO documents (
         id, root_id, type_id, version_number, is_current_draft, is_published, status,
         parent_root_id, slug, title, tenant_id, locale, translation_group_id,
         data, metadata, created_at, updated_at
       ) VALUES (?, ?, 'plugin', 1, 1, 1, 'published', '', ?, ?, 'default', 'default', '', ?, '{}', 1, 1)`
    )
    .bind(slug, slug, slug, slug, data)
    .run()
}

describe('PluginBootstrapService.isBootstrapNeeded (real SQLite)', () => {
  let db

  beforeEach(async () => {
    db = createTestD1()
    await db.prepare(PLUGIN_TYPE_SQL).run()
  })

  afterEach(() => {
    db?.close?.()
  })

  it('is needed on an empty database', async () => {
    expect(await new PluginBootstrapService(db).isBootstrapNeeded()).toBe(true)
  })

  it('is still needed when only the core-* plugins made it in', async () => {
    await installPlugin(db, 'core-auth')
    await installPlugin(db, 'core-media')

    // The defect: these two are the whole bootstrap list minus core-*, and the gate could not
    // see them, so a boot interrupted after core-media was never retried.
    expect(await new PluginBootstrapService(db).isBootstrapNeeded()).toBe(true)
  })

  it('is not needed once every bootstrapped plugin is installed and active', async () => {
    for (const slug of BOOTSTRAPPED) await installPlugin(db, slug)

    expect(await new PluginBootstrapService(db).isBootstrapNeeded()).toBe(false)
  })

  it('leaves a deactivated non-core plugin deactivated', async () => {
    for (const slug of BOOTSTRAPPED) await installPlugin(db, slug)
    await db
      .prepare(`UPDATE documents SET data = json_set(data, '$.status', 'inactive') WHERE slug = ?`)
      .bind('lexical-editor')
      .run()

    // Turning the editor off in the admin UI has to survive the next cold start — re-running
    // bootstrap would activate it again, because ensurePluginInstalled activates anything in
    // the list that is currently inactive.
    expect(await new PluginBootstrapService(db).isBootstrapNeeded()).toBe(false)
  })

  it('is needed again when a core-* plugin is left inactive', async () => {
    for (const slug of BOOTSTRAPPED) await installPlugin(db, slug)
    await db
      .prepare(`UPDATE documents SET data = json_set(data, '$.status', 'inactive') WHERE slug = ?`)
      .bind('core-auth')
      .run()

    // Nothing in the admin UI offers to turn auth off, so an inactive core-* row is damage.
    expect(await new PluginBootstrapService(db).isBootstrapNeeded()).toBe(true)
  })

  it('ignores another tenant and soft-deleted rows', async () => {
    for (const slug of BOOTSTRAPPED) await installPlugin(db, slug)
    await db
      .prepare(`UPDATE documents SET tenant_id = 'other' WHERE slug = ?`)
      .bind('lexical-editor')
      .run()

    expect(await new PluginBootstrapService(db).isBootstrapNeeded()).toBe(true)

    await db.prepare(`UPDATE documents SET tenant_id = 'default' WHERE slug = ?`).bind('lexical-editor').run()
    await db.prepare(`UPDATE documents SET deleted_at = 99 WHERE slug = ?`).bind('two-factor-auth').run()

    expect(await new PluginBootstrapService(db).isBootstrapNeeded()).toBe(true)
  })
})
