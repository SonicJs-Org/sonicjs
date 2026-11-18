// @ts-nocheck
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../../utils/d1-sqlite'
import { PLUGIN_REGISTRY } from '../../../plugins/manifest-registry'
import { queryTracePlugin } from '../../../plugins/core-plugins/query-trace-plugin'
import { DEFAULT_QUERY_TRACE_SETTINGS } from '../../../plugins/core-plugins/query-trace-plugin/constants'
import { applySchemaDefaults } from '../../../plugins/sdk/config-schema'
import { PluginBootstrapService } from '../../../services/plugin-bootstrap'
import { PluginService } from '../../../services/plugin-service'

const PLUGIN_TYPE_SQL = `
  INSERT INTO document_types (id, name, display_name, schema, queryable_fields, settings, source, schema_version, is_system, is_active, created_at, updated_at)
  VALUES ('plugin','plugin','Plugin','{}','[]','{}','system',1,1,1,1,1)
`

describe('query-trace plugin registration', () => {
  it('is in the registry as available, non-core, not defaultActive', () => {
    const entry = PLUGIN_REGISTRY['query-trace']
    expect(entry).toBeDefined()
    expect(entry.is_core).toBe(false)
    expect(entry.defaultActive).toBeFalsy()
  })

  it('configSchema defaults equal manifest defaultSettings', () => {
    const defaults = applySchemaDefaults(queryTracePlugin.configSchema!, {})
    expect(defaults).toEqual(PLUGIN_REGISTRY['query-trace'].defaultSettings)
    expect(defaults).toEqual(DEFAULT_QUERY_TRACE_SETTINGS)
  })
})

describe('query-trace lifecycle (real SQLite)', () => {
  let db
  beforeEach(async () => {
    db = createTestD1()
    await db.prepare(PLUGIN_TYPE_SQL).run()
    await db.applyScalarSchema('plugin', [
      { name: 'status', kind: 'scalar', type: 'text', column: 'q_plugin_status' },
      { name: 'category', kind: 'scalar', type: 'text', column: 'q_plugin_category' },
      { name: 'isCore', kind: 'scalar', type: 'integer', column: 'q_plugin_is_core' },
    ])
  })
  afterEach(() => db?.close?.())

  it('is not installed by PluginBootstrapService', async () => {
    await new PluginBootstrapService(db).bootstrapCorePlugins()
    expect(await new PluginService(db).getPlugin('query-trace')).toBeNull()
  })

  it('install -> active, deactivate -> inactive', async () => {
    const svc = new PluginService(db)
    const installed = await svc.installPlugin({ id: 'query-trace', display_name: 'Query Trace' })
    expect(installed.status).toBe('active')
    await svc.deactivatePlugin('query-trace')
    expect((await svc.getPlugin('query-trace')).status).toBe('inactive')
  })
})
