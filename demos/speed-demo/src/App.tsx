import { useState, useEffect, useCallback, useRef } from 'react'
import { sonic, sonicOrigin, useMock } from './lib/client'
import { fetchPayloadEmployees } from './lib/payload-client'
import { DEPT_MAP, REGION_MAP, DEPT_OPTIONS, REGION_OPTIONS } from './lib/static-data'
import type {
  EmployeeRecord,
  FilterState,
  PayloadEmployee,
} from './types'
import { EmployeeCard } from './components/EmployeeCard'
import { PayloadCard } from './components/PayloadCard'
import { FilterGroup } from './components/Filters'
import { Pagination } from './components/Pagination'
import { StatsBar } from './components/StatsBar'
import { FAQ } from './components/FAQ'

const PAGE_SIZE = 10

function Dots({ color }: { color: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      {[0, 150, 300].map((delay) => (
        <span
          key={delay}
          className={`w-2 h-2 rounded-full animate-bounce ${color}`}
          style={{ animationDelay: `${delay}ms` }}
        />
      ))}
    </span>
  )
}

function Skeleton({ variant }: { variant: 'sonic' | 'payload' }) {
  const border = variant === 'sonic' ? 'border-white/10' : 'border-orange-500/10'
  return (
    <div className={`bg-slate-900 border ${border} rounded-xl p-4 animate-pulse`}>
      <div className="flex items-start gap-3">
        <div className="w-12 h-12 rounded-full bg-slate-800 flex-shrink-0" />
        <div className="flex-1 space-y-2 pt-1">
          <div className="h-3 bg-slate-800 rounded w-3/4" />
          <div className="h-2.5 bg-slate-800 rounded w-1/2" />
          <div className="h-5 bg-slate-800 rounded-full w-24 mt-1" />
        </div>
      </div>
      <div className="mt-3 pt-3 border-t border-white/5 space-y-1.5">
        <div className="h-2.5 bg-slate-800 rounded w-full" />
        <div className="h-2.5 bg-slate-800 rounded w-1/3" />
      </div>
    </div>
  )
}

export function App() {
  const [showFAQ, setShowFAQ] = useState(() => window.location.hash === '#how-it-works')

  useEffect(() => {
    const onHash = () => setShowFAQ(window.location.hash === '#how-it-works')
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  const goFAQ  = () => { window.location.hash = 'how-it-works' }
  const goDemo = () => { window.location.hash = '' }

  // ── SonicJS state ──────────────────────────────────────────────────────────
  const [employees, setEmployees] = useState<EmployeeRecord[]>([])
  const [sonicLoading, setSonicLoading] = useState(false)
  const [sonicMs, setSonicMs] = useState<number | null>(null)
  const [cacheSource, setCacheSource] = useState<string | null>(null)
  const edgeMode = true  // always edge; no toggle in comparison view
  const [pageCount, setPageCount] = useState(0)
  const [hasNextPage, setHasNextPage] = useState(false)
  const [page, setPage] = useState(0)
  const [filters, setFilters] = useState<FilterState>({ department: '', region: '' })

  // ── Payload state ──────────────────────────────────────────────────────────
  const [payloadEmployees, setPayloadEmployees] = useState<PayloadEmployee[]>([])
  const [payloadLoading, setPayloadLoading] = useState(false)
  const [payloadMs, setPayloadMs] = useState<number | null>(null)
  const [totalDocs, setTotalDocs] = useState<number | null>(null)

  // ── Reference data (hardcoded — fixed seed records, no API calls needed) ────
  const deptMap = DEPT_MAP
  const regionMap = REGION_MAP
  const deptOptions = DEPT_OPTIONS
  const regionOptions = REGION_OPTIONS


  // Monotonic counter — discard results from superseded fetches
  const fetchSeqRef = useRef(0)

  const fetchAllTimed = useCallback(
    async (currentPage: number, currentFilters: FilterState, bypassCache = false) => {
      const seq = ++fetchSeqRef.current
      setSonicMs(null)
      setPayloadMs(null)
      setSonicLoading(true)
      setPayloadLoading(true)

      const where: Record<string, Record<string, string>> = {}
      if (currentFilters.department) where['data.department'] = { equals: currentFilters.department }
      if (currentFilters.region) where['data.region'] = { equals: currentFilters.region }

      const sonicClient = (!useMock && bypassCache) ? sonicOrigin : sonic

      // Both fire at the same time — Payload resolves independently so the race is real
      const sonicPromise = (async () => {
        const t0 = performance.now()
        try {
          const { data: response, headers } = await sonicClient
            .collection('employees')
            .listWithHeaders({
              limit: PAGE_SIZE,
              offset: currentPage * PAGE_SIZE,
              status: 'published',
              // Match Payload's explicit sort so both sides render employees in the same order.
              // Sort by phone (unique per employee) — first/last name had too many duplicates.
              sort: JSON.stringify([
                { field: 'data.phone', order: 'asc' },
              ]),
              ...(Object.keys(where).length ? { where } : {}),
            })
          if (seq !== fetchSeqRef.current) return
          setSonicMs(Math.round(performance.now() - t0))
          setCacheSource(headers.get('x-cache-source') ?? headers.get('sonicjs-source'))
          setEmployees(response.data as unknown as EmployeeRecord[])
          setPageCount(response.meta.count)
          setHasNextPage(response.meta.count === PAGE_SIZE)
        } catch (err) {
          console.error('SonicJS error:', err)
        } finally {
          if (seq === fetchSeqRef.current) setSonicLoading(false)
        }
      })()

      const payloadPromise = (async () => {
        try {
          const deptName = currentFilters.department ? DEPT_MAP.get(currentFilters.department)?.name : undefined
          const regionName = currentFilters.region ? REGION_MAP.get(currentFilters.region)?.name : undefined
          const { docs, ms, totalDocs: total } = await fetchPayloadEmployees(currentPage + 1, PAGE_SIZE, deptName, regionName)
          if (seq !== fetchSeqRef.current) return
          setPayloadEmployees(docs)
          setPayloadMs(ms)
          if (total != null) setTotalDocs(total)
        } catch (err) {
          console.error('Payload error:', err)
        } finally {
          if (seq === fetchSeqRef.current) setPayloadLoading(false)
        }
      })()

      await Promise.allSettled([sonicPromise, payloadPromise])
    },
    [],
  )

  useEffect(() => {
    fetchAllTimed(page, filters, !edgeMode)
  }, [page, filters, edgeMode, fetchAllTimed])

  const handleFilterChange = (newFilters: FilterState) => {
    setPage(0)
    setFilters(newFilters)
  }

  const skeletons = Array.from({ length: PAGE_SIZE })

  return (
    <div className="min-h-screen bg-slate-950">

      {/* ── Header ── */}
      <header className="border-b border-white/10 bg-slate-950/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="px-4 sm:px-6 lg:px-8 py-3 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            <div className="w-8 h-8 bg-emerald-400 rounded-lg flex items-center justify-center flex-shrink-0">
              <span className="text-slate-900 font-bold text-sm">S</span>
            </div>
            <div className="min-w-0">
              <h1 className="text-white font-semibold text-sm sm:text-base leading-tight">
                SonicJS Speed Demo
              </h1>
              <p className="text-slate-500 text-xs hidden sm:block">
                SonicJS Edge vs Payload CMS
                {useMock && <span className="ml-1 text-yellow-500/80">· mock data</span>}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-1.5 flex-shrink-0">
            <button
              onClick={() => showFAQ ? goDemo() : goFAQ()}
              className={`text-xs font-medium px-3 py-1.5 rounded-lg border transition-colors ${
                showFAQ
                  ? 'bg-emerald-400/10 border-emerald-500/40 text-emerald-300'
                  : 'bg-transparent border-white/10 text-slate-400 hover:text-white hover:border-white/20'
              }`}
            >
              {showFAQ ? '← Demo' : 'How it works'}
            </button>

            {!showFAQ && (
              <button
                onClick={() => fetchAllTimed(page, filters)}
                disabled={sonicLoading || payloadLoading}
                title="Refresh data"
                className="w-7 h-7 flex items-center justify-center rounded-lg border border-white/10 text-slate-400 hover:text-white hover:border-white/20 transition-colors disabled:opacity-30"
              >
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  viewBox="0 0 16 16"
                  fill="currentColor"
                  className={`w-3.5 h-3.5 ${sonicLoading || payloadLoading ? 'animate-spin' : ''}`}
                >
                  <path fillRule="evenodd" d="M13.836 2.477a.75.75 0 0 1 .75.75v3.182a.75.75 0 0 1-.75.75h-3.182a.75.75 0 0 1 0-1.5h1.37l-.84-.841a4.5 4.5 0 0 0-7.08.932.75.75 0 0 1-1.3-.75 6 6 0 0 1 9.44-1.242l.842.84V3.227a.75.75 0 0 1 .75-.75Zm-.911 7.5A.75.75 0 0 1 13.199 11a6 6 0 0 1-9.44 1.241l-.84-.84v1.371a.75.75 0 0 1-1.5 0V9.591a.75.75 0 0 1 .75-.75H5.35a.75.75 0 0 1 0 1.5H3.98l.841.841a4.5 4.5 0 0 0 7.08-.932.75.75 0 0 1 1.025-.273Z" clipRule="evenodd" />
                </svg>
              </button>
            )}
          </div>

        </div>
      </header>

      {/* ── FAQ page ── */}
      {showFAQ && <FAQ />}

      {/* ── Main demo content (hidden when FAQ is open) ── */}
      {!showFAQ && <>

      {/* ── Filters + Speed Boost (1 row, 3 cols) ── */}
      <div className="border-b border-white/5 bg-slate-950/60 px-4 sm:px-6 lg:px-8 py-3">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 items-start">

          {/* Col 1 — Dept */}
          <FilterGroup
            label="Dept"
            options={deptOptions}
            active={filters.department}
            onSelect={(id) => handleFilterChange({ ...filters, department: id })}
            renderLabel={(o) => `${o.icon ? o.icon + ' ' : ''}${o.name}`}
          />

          {/* Col 2 — Region */}
          <FilterGroup
            label="Region"
            options={regionOptions}
            active={filters.region}
            onSelect={(id) => handleFilterChange({ ...filters, region: id })}
            renderLabel={(o) => `${o.flag ? o.flag + ' ' : ''}${o.name}`}
          />

          {/* Col 3 — Speed Boost card */}
          <div className="flex flex-col gap-2">
            <StatsBar sonicMs={sonicMs} payloadMs={payloadMs} sonicSource={cacheSource} />
            {(filters.department || filters.region) && (
              <button
                onClick={() => handleFilterChange({ department: '', region: '' })}
                className="text-xs text-slate-400 hover:text-white border border-white/10 rounded-lg px-3 py-1 transition-colors self-start"
              >
                Clear filters
              </button>
            )}
          </div>

        </div>
      </div>

      {/* ── Race grid ── */}
      <div className="px-4 sm:px-6 lg:px-8 py-5">

        {/* Column labels */}
        <div className="grid grid-cols-2 gap-6 mb-3">
          <div className="flex items-center gap-2 px-1">
            <div className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">⚡ SonicJS Edge</span>
            {sonicMs !== null && (
              <span className="text-xs text-slate-500 font-mono ml-auto">{sonicMs}ms</span>
            )}
          </div>
          <div className="flex items-center gap-2 px-1">
            <div className="w-1.5 h-1.5 rounded-full bg-orange-400" />
            <span className="text-xs font-semibold text-orange-400 uppercase tracking-wider">🐢 Payload CMS</span>
            {payloadMs !== null && (
              <span className="text-xs text-slate-500 font-mono ml-auto">{payloadMs}ms</span>
            )}
          </div>
        </div>

        {/* Layout: 2 cols side-by-side on mobile, same 2 cols from lg up */}
        <div className="grid grid-cols-2 lg:grid-cols-[1fr_1px_1fr] gap-x-3 sm:gap-x-6 gap-y-6">

          {/* SonicJS side */}
          <div className="flex flex-col gap-3">
            {/* SonicJS stat card */}
            <div className="bg-slate-900 border border-emerald-500/20 rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-1.5">
                  <span className="text-emerald-400 text-sm">⚡</span>
                  <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">SonicJS</span>
                </div>
                {cacheSource && (
                  <span className="text-xs text-emerald-500/70 bg-emerald-500/10 px-2 py-0.5 rounded-full">
                    {cacheSource}
                  </span>
                )}
              </div>
              <div className={`text-2xl font-bold font-mono tracking-tight mb-2 ${
                sonicMs === null ? 'text-slate-400'
                : sonicMs < 50 ? 'text-emerald-400'
                : sonicMs < 200 ? 'text-yellow-400'
                : 'text-red-400'
              }`}>
                {sonicMs !== null ? `${sonicMs}ms` : <Dots color="bg-emerald-400" />}
              </div>
              <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-emerald-400 rounded-full transition-all duration-700 ease-out"
                  style={{ width: sonicMs !== null ? `${Math.max((sonicMs / Math.max(sonicMs ?? 0, payloadMs ?? 0, 400)) * 100, 2)}%` : '0%' }}
                />
              </div>
              <p className="text-xs text-slate-600 mt-1">Cloudflare Workers + D1</p>
            </div>

            {/* Employee cards */}
            <div
              className="grid grid-cols-1 sm:grid-cols-2 gap-3 content-start"
              style={{ opacity: sonicLoading && employees.length > 0 ? 0.5 : 1, transition: 'opacity 150ms' }}
            >
            {sonicLoading && employees.length === 0
              ? skeletons.map((_, i) => <Skeleton key={i} variant="sonic" />)
              : employees.map((emp) => (
                  <EmployeeCard key={emp.id} employee={emp} deptMap={deptMap} regionMap={regionMap} />
                ))
            }
            </div>
          </div>

          {/* Divider */}
          <div className="bg-white/5 self-stretch hidden lg:block" />

          {/* Payload side */}
          <div className="flex flex-col gap-3">
            {/* Payload stat card */}
            <div className="bg-slate-900 border border-orange-500/20 rounded-xl p-4">
              <div className="flex items-center gap-1.5 mb-2">
                <span className="text-orange-400 text-sm">🐢</span>
                <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Payload</span>
              </div>
              <div className={`text-2xl font-bold font-mono tracking-tight mb-2 ${
                payloadMs === null ? 'text-slate-400'
                : payloadMs < 300 ? 'text-yellow-400'
                : 'text-red-400'
              }`}>
                {payloadMs !== null ? `${payloadMs}ms` : <Dots color="bg-orange-400" />}
              </div>
              <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-orange-400 rounded-full transition-all duration-700 ease-out"
                  style={{ width: payloadMs !== null ? `${Math.max((payloadMs / Math.max(sonicMs ?? 0, payloadMs ?? 0, 400)) * 100, 2)}%` : '0%' }}
                />
              </div>
              <p className="text-xs text-slate-600 mt-1">Cloudflare Workers + D1 (no cache)</p>
            </div>

            {/* Employee cards */}
            <div
              className="grid grid-cols-1 sm:grid-cols-2 gap-3 content-start"
              style={{ opacity: payloadLoading && payloadEmployees.length > 0 ? 0.5 : 1, transition: 'opacity 150ms' }}
            >
            {payloadLoading && payloadEmployees.length === 0
              ? skeletons.map((_, i) => <Skeleton key={i} variant="payload" />)
              : payloadEmployees.map((emp) => (
                  <PayloadCard key={emp.id} employee={emp} />
                ))
            }
            </div>
          </div>

        </div>

        {/* Pagination */}
        {(page > 0 || hasNextPage) && (
          <div className="mt-5">
            <Pagination
              page={page}
              pageSize={PAGE_SIZE}
              count={pageCount}
              hasNext={hasNextPage}
              onPrev={() => setPage((p) => p - 1)}
              onNext={() => setPage((p) => p + 1)}
            />
          </div>
        )}

        {/* Total record count */}
        {totalDocs != null && (
          <div className="mt-6 pt-4 border-t border-white/5 text-center">
            <span className="text-xs text-slate-600">
              {totalDocs.toLocaleString()} {filters.department || filters.region ? 'matching Payload employees' : 'total employees across both backends'}
            </span>
          </div>
        )}
      </div>

      </>}
    </div>
  )
}
