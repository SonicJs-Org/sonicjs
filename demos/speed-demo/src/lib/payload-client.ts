import type { PayloadEmployee } from '../types'

export interface PayloadListResult {
  docs: PayloadEmployee[]
  totalDocs: number
  page: number
  totalPages: number
  ms: number
}

// Dev: use vite proxy (/payload-api → https://payload.sonicjs.com/api) to avoid CORS
// Prod: call directly — Payload has cors: '*'
const PAYLOAD_BASE = import.meta.env.DEV
  ? '/payload-api'
  : 'https://payload.sonicjs.com/api'

export async function fetchPayloadEmployees(
  page = 1,
  limit = 10,
  department?: string,
  region?: string,
): Promise<PayloadListResult> {
  const params = new URLSearchParams({
    limit: String(limit),
    depth: '1',
    page: String(page),
    // Match SonicJS's explicit sort so both sides render employees in the same order.
    // Sort by phone (unique per employee) — first/last name had too many duplicates.
    sort: 'phone',
  })
  if (department) params.set('where[department.name][equals]', department)
  if (region) params.set('where[region.name][equals]', region)

  const t0 = performance.now()
  const res = await fetch(`${PAYLOAD_BASE}/employees?${params}`)
  const json = await res.json()
  return {
    ...json,
    ms: Math.round(performance.now() - t0),
  }
}
