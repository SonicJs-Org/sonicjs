/**
 * Dependency-aware plugin ordering (topo-sort + cycle detection).
 *
 * Plugins declare `dependencies: ['other-plugin-id']`. This module produces a
 * dependency-first order — so a plugin that depends on another is mounted and
 * wired AFTER the dependency, not before. Today the `dependencies` field is
 * inert (plugins are mounted/wired in declaration order). This makes it real.
 *
 * Reference: Infowall `register-plugins.ts` `topoSort`. The algorithm is the
 * same iterative DFS with a `visiting` stack that Infowall uses, adapted to
 * the structural plugin shape used here.
 */

/** Thrown when `topoSort` detects a dependency cycle. */
export class PluginDependencyCycleError extends Error {
  readonly cycle: string[]
  constructor(pluginId: string, visitStack: string[]) {
    const idx = visitStack.indexOf(pluginId)
    const cycle = idx >= 0 ? [...visitStack.slice(idx), pluginId] : [...visitStack, pluginId]
    super(`Plugin dependency cycle detected: ${cycle.join(' → ')}`)
    this.name = 'PluginDependencyCycleError'
    this.cycle = cycle
  }
}

/** Minimal structural shape this module needs from a plugin. */
export interface SortablePlugin {
  /** Stable unique identifier. Falls back to `name` when `id` is absent. */
  id?: string
  name?: string
  /** IDs of plugins that must be mounted/wired before this one. */
  dependencies?: string[]
}

export interface TopoSortOptions {
  /**
   * When true, an unknown dependency id → throw. When false (default), emit a
   * console.warn and skip the dependency (graceful degradation).
   */
  strict?: boolean
}

/**
 * Sort `plugins` into dependency-first order.
 *
 * Plugins with no `dependencies` field (old-style PluginBuilder plugins) sort
 * at the front in their original declaration order, before any v3 plugins that
 * might depend on them — this preserves backwards compatibility.
 *
 * @throws {PluginDependencyCycleError} if a dependency cycle is detected.
 */
export function topoSort<T extends SortablePlugin>(
  plugins: ReadonlyArray<T>,
  options: TopoSortOptions = {}
): T[] {
  const byId = new Map<string, T>()
  for (const p of plugins) {
    const id = pluginId(p)
    if (id) byId.set(id, p)
  }

  const result: T[] = []
  const visited = new Set<string>()
  const visiting = new Set<string>()

  function visit(p: T): void {
    const id = pluginId(p) ?? Math.random().toString()
    if (visited.has(id)) return
    if (visiting.has(id)) throw new PluginDependencyCycleError(id, [...visiting])

    visiting.add(id)
    for (const dep of p.dependencies ?? []) {
      const depPlugin = byId.get(dep)
      if (!depPlugin) {
        if (options.strict) {
          throw new Error(
            `Plugin "${id}" depends on "${dep}" which is not in the plugin list.`
          )
        } else {
          console.warn(
            `[plugins] Plugin "${id}" declares dependency "${dep}" which is not registered. ` +
              `The dependency will be skipped — boot order may be incorrect.`
          )
        }
        continue
      }
      visit(depPlugin)
    }

    visiting.delete(id)
    visited.add(id)
    result.push(p)
  }

  for (const p of plugins) visit(p)
  return result
}

function pluginId(p: SortablePlugin): string | undefined {
  return (p as any).id ?? p.name ?? undefined
}
