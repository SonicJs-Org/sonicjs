import type { PayloadEmployee } from '../types'

export interface PayloadListResult {
  docs: PayloadEmployee[]
  totalDocs: number
  page: number
  totalPages: number
  ms: number
}

export async function fetchPayloadEmployees(
  page = 1,
  limit = 10,
): Promise<PayloadListResult> {
  const t0 = performance.now()
  // Use vite proxy (/payload-api → https://payload.sonicjs.com/api) to avoid CORS in dev
  const res = await fetch(
    `/payload-api/employees?limit=${limit}&depth=1&page=${page}`,
  )
  const json = await res.json()
  return {
    ...json,
    ms: Math.round(performance.now() - t0),
  }
}
