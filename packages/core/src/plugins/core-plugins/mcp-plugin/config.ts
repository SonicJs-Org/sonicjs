/**
 * MCP plugin configuration.
 *
 * Config is supplied in code when the operator adds `mcpPlugin({...})` to the app's
 * plugin register array — captured in a closure and resolved against the live
 * CollectionRegistry on each request (so newly registered collections appear
 * without a restart). All fields are optional with safe defaults.
 */

import { z } from 'zod'
import type { CollectionRecord } from '../../../services/collection-registry'

export const mcpTypeConfigSchema = z.object({
  read: z.boolean().default(true),
  write: z.boolean().default(true),
})

export const mcpConfigSchema = z.object({
  /** Collections exposed over MCP. Omitted → every active collection. */
  expose: z.array(z.string()).optional(),
  /** Per-collection read/write overrides, keyed by collection name. */
  types: z.record(z.string(), mcpTypeConfigSchema).default({}),
  /** Field names stripped from every tool response + write schema. */
  redactFields: z.array(z.string()).default([]),
  /** Max documents returned by list_* tools and document resources. */
  listLimit: z.number().int().positive().max(200).default(50),
})

export type McpConfigInput = z.input<typeof mcpConfigSchema>
export type McpConfig = z.infer<typeof mcpConfigSchema>

export interface ResolvedMcpType {
  typeId: string
  displayName: string
  read: boolean
  write: boolean
}

export interface ResolvedMcpConfig {
  types: ResolvedMcpType[]
  redactFields: string[]
  listLimit: number
}

/**
 * Expand raw config against the live registry: apply the `expose` filter, fill
 * per-type read/write defaults, and resolve display names. Only active
 * collections are considered.
 */
export function resolveMcpConfig(
  raw: McpConfigInput | undefined,
  collections: CollectionRecord[],
): ResolvedMcpConfig {
  const cfg = mcpConfigSchema.parse(raw ?? {})
  const exposeSet = cfg.expose ? new Set(cfg.expose) : null

  const types: ResolvedMcpType[] = collections
    .filter((c) => (exposeSet ? exposeSet.has(c.name) : true))
    .map((c) => {
      const override = cfg.types[c.name]
      return {
        typeId: c.name,
        displayName: c.displayName ?? c.name,
        read: override?.read ?? true,
        write: override?.write ?? true,
      }
    })

  return { types, redactFields: cfg.redactFields, listLimit: cfg.listLimit }
}
