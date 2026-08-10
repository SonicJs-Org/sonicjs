import { resolve } from 'node:path'
import { type SdkCollectionConfig } from './types'

export async function fetchSchemaFromUrl(
  url: string,
  apiKey?: string,
): Promise<SdkCollectionConfig[]> {
  const base = url.replace(/\/$/, '')
  const headers: Record<string, string> = {}
  if (apiKey) headers['x-api-key'] = apiKey

  const res = await fetch(`${base}/api/collections`, { headers })
  if (!res.ok) {
    throw new Error(`Failed to fetch collections from ${base}: ${res.status} ${res.statusText}`)
  }

  const json = (await res.json()) as { data?: SdkCollectionConfig[] }
  if (!Array.isArray(json?.data)) {
    throw new Error(`Unexpected response shape from /api/collections`)
  }
  return json.data
}

export async function fetchSchemaFromConfig(configPath: string): Promise<SdkCollectionConfig[]> {
  const absPath = resolve(process.cwd(), configPath)
  const mod = (await import(absPath)) as
    | SdkCollectionConfig[]
    | { default?: SdkCollectionConfig[] | { collections?: SdkCollectionConfig[] } }

  const raw = Array.isArray(mod)
    ? mod
    : ((mod as { default?: unknown }).default ?? mod)

  const configs = Array.isArray(raw)
    ? raw
    : (raw as { collections?: SdkCollectionConfig[] })?.collections ?? []

  if (!Array.isArray(configs)) {
    throw new Error(
      `Config at ${configPath} must export an array of CollectionConfig (or { collections: CollectionConfig[] })`,
    )
  }
  return configs as SdkCollectionConfig[]
}
