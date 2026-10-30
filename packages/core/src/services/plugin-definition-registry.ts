/**
 * In-memory registry of registered plugin definitions, indexed by id.
 *
 * Populated by `registerPlugins()` at app construction. The admin settings
 * route uses it to look up a plugin's `configSchema` so the schema-driven
 * settings form can be auto-rendered without per-plugin glue code.
 *
 * Read by the admin layer; written ONLY by registerPlugins.
 */

import type { RegisterablePlugin } from '../plugins/sdk/register-plugins'

let registry: ReadonlyMap<string, RegisterablePlugin> = new Map()

export function setPluginDefinitions(plugins: ReadonlyArray<RegisterablePlugin>): void {
  const next = new Map<string, RegisterablePlugin>()
  for (const p of plugins) next.set(p.id, p)
  registry = next
}

export function getPluginDefinition(id: string): RegisterablePlugin | undefined {
  return registry.get(id)
}

export function getAllPluginDefinitions(): ReadonlyArray<RegisterablePlugin> {
  return Array.from(registry.values())
}

export function resetPluginDefinitions(): void {
  registry = new Map()
}
