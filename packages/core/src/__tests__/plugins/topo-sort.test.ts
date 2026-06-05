/**
 * Tests for T3.1 — dependency topo-sort + cycle detection.
 */
import { describe, it, expect } from 'vitest'
import { topoSort, PluginDependencyCycleError } from '../../plugins/topo-sort'

function ids(plugins: Array<{ id?: string; name?: string }>): string[] {
  return plugins.map((p) => p.id ?? p.name ?? '?')
}

describe('topoSort', () => {
  it('returns plugins with no dependencies in their original order', () => {
    const plugins = [{ name: 'A' }, { name: 'B' }, { name: 'C' }]
    expect(ids(topoSort(plugins))).toEqual(['A', 'B', 'C'])
  })

  it('[B(deps:[A]), A] → A before B', () => {
    const plugins = [
      { name: 'B', dependencies: ['A'] },
      { name: 'A' },
    ]
    const sorted = ids(topoSort(plugins))
    expect(sorted.indexOf('A')).toBeLessThan(sorted.indexOf('B'))
  })

  it('transitive: C(deps:[B]), B(deps:[A]), A → A, B, C', () => {
    const plugins = [
      { name: 'C', dependencies: ['B'] },
      { name: 'A' },
      { name: 'B', dependencies: ['A'] },
    ]
    const sorted = ids(topoSort(plugins))
    expect(sorted.indexOf('A')).toBeLessThan(sorted.indexOf('B'))
    expect(sorted.indexOf('B')).toBeLessThan(sorted.indexOf('C'))
  })

  it('plugins without dependencies come before those with dependencies', () => {
    const plugins = [
      { name: 'B', dependencies: ['A'] },
      { name: 'C', dependencies: ['A'] },
      { name: 'A' },
    ]
    const sorted = ids(topoSort(plugins))
    expect(sorted[0]).toBe('A')
    expect(sorted).toContain('B')
    expect(sorted).toContain('C')
  })

  it('throws PluginDependencyCycleError on a direct cycle (A→B→A)', () => {
    const plugins = [
      { name: 'A', dependencies: ['B'] },
      { name: 'B', dependencies: ['A'] },
    ]
    expect(() => topoSort(plugins)).toThrow(PluginDependencyCycleError)
  })

  it('throws PluginDependencyCycleError on a transitive cycle (A→B→C→A)', () => {
    const plugins = [
      { name: 'A', dependencies: ['C'] },
      { name: 'B', dependencies: ['A'] },
      { name: 'C', dependencies: ['B'] },
    ]
    expect(() => topoSort(plugins)).toThrow(PluginDependencyCycleError)
  })

  it('PluginDependencyCycleError.cycle includes the cycle path', () => {
    const plugins = [
      { name: 'A', dependencies: ['B'] },
      { name: 'B', dependencies: ['A'] },
    ]
    let err: PluginDependencyCycleError | undefined
    try {
      topoSort(plugins)
    } catch (e) {
      err = e as PluginDependencyCycleError
    }
    expect(err).toBeInstanceOf(PluginDependencyCycleError)
    expect(err!.cycle.length).toBeGreaterThanOrEqual(2)
  })

  it('missing dependency id — warns in non-strict mode, skips gracefully', () => {
    const warns: string[] = []
    const origWarn = console.warn
    console.warn = (...args: any[]) => warns.push(args.join(' '))
    try {
      const plugins = [{ name: 'B', dependencies: ['A-missing'] }, { name: 'C' }]
      const sorted = ids(topoSort(plugins, { strict: false }))
      expect(sorted).toContain('B')
      expect(sorted).toContain('C')
      expect(warns.some((w) => w.includes('A-missing'))).toBe(true)
    } finally {
      console.warn = origWarn
    }
  })

  it('missing dependency id — throws in strict mode', () => {
    const plugins = [{ name: 'B', dependencies: ['A-missing'] }]
    expect(() => topoSort(plugins, { strict: true })).toThrow('A-missing')
  })

  it('uses `id` field when present (preferred over `name`) for lookup and output', () => {
    const plugins = [
      { id: 'plugin-b', name: 'B', dependencies: ['plugin-a'] },
      { id: 'plugin-a', name: 'A' },
    ]
    // ids() returns id when present
    const sorted = ids(topoSort(plugins))
    expect(sorted.indexOf('plugin-a')).toBeLessThan(sorted.indexOf('plugin-b'))
  })
})
