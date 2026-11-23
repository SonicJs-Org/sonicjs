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
): Promise<PayloadListResult> {
  const t0 = performance.now()
  const res = await fetch(
    `${PAYLOAD_BASE}/employees?limit=${limit}&depth=1&page=${page}`,
  )
  const json = await res.json()
  return {
    ...json,
    ms: Math.round(performance.now() - t0),
  }
}
