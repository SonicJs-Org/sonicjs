import { createClient } from '@sonicjs-cms/sdk'
import { mockFetch } from './mock-data'

const CMS_URL = import.meta.env['VITE_CMS_URL'] as string | undefined
const API_KEY = import.meta.env['VITE_API_KEY'] as string | undefined

const useMock = !CMS_URL

export const sonic = createClient({
  url: CMS_URL ?? 'https://demo.sonicjs.com',
  apiKey: API_KEY,
  fetch: useMock ? (mockFetch as typeof fetch) : undefined,
})

/** Client that sends Cache-Control: no-cache to bypass the edge cache and hit origin/DB. */
export const sonicOrigin = createClient({
  url: CMS_URL ?? 'https://demo.sonicjs.com',
  apiKey: API_KEY,
  headers: { 'Cache-Control': 'no-cache' },
})

export { useMock }
