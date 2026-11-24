import { useState, useEffect, useCallback } from 'react'
import { sonic, sonicOrigin, useMock } from './lib/client'
import { fetchPayloadEmployees } from './lib/payload-client'
import type {
  EmployeeRecord, DepartmentRecord, RegionRecord,
  DeptMap, RegionMap, FilterOption, FilterState,
  PayloadEmployee,
} from './types'
import { EmployeeCard } from './components/EmployeeCard'
import { PayloadCard } from './components/PayloadCard'
import { Filters } from './components/Filters'
import { Pagination } from './components/Pagination'
import { StatsBar } from './components/StatsBar'

const PAGE_SIZE = 10

const DEPT_TAILWIND: Record<string, string> = {
  Engineering: 'bg-blue-500/20 text-blue-300',
  Product:     'bg-purple-500/20 text-purple-300',
  Design:      'bg-pink-500/20 text-pink-300',
  Marketing:   'bg-orange-500/20 text-orange-300',
  Sales:       'bg-green-500/20 text-green-300',
  HR:          'bg-teal-500/20 text-teal-300',
  Finance:     'bg-yellow-500/20 text-yellow-300',
  Legal:       'bg-red-500/20 text-red-300',
  Operations:  'bg-slate-500/20 text-slate-300',
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

  // ── Reference data ─────────────────────────────────────────────────────────
  const [deptMap, setDeptMap] = useState<DeptMap>(new Map())
  const [regionMap, setRegionMap] = useState<RegionMap>(new Map())
  const [deptOptions, setDeptOptions] = useState<FilterOption[]>([])
  const [regionOptions, setRegionOptions] = useState<FilterOption[]>([])

  useEffect(() => {
    const loadRefs = async () => {
      const [deptsRes, regionsRes] = await Promise.all([
        sonic.collection('departments').list({ limit: 50, status: 'published' }),
        sonic.collection('regions').list({ limit: 50, status: 'published' }),
      ])

      const newDeptMap: DeptMap = new Map()
      const newDeptOptions: FilterOption[] = []
      for (const rec of deptsRes.data as unknown as DepartmentRecord[]) {
        const name = rec.data.name
        newDeptMap.set(rec.id, {
          name,
          icon: rec.data.icon ?? '',
          color: rec.data.color ?? '#64748B',
          tailwindClass: DEPT_TAILWIND[name] ?? 'bg-slate-500/20 text-slate-300',
        })
        newDeptOptions.push({ id: rec.id, name, icon: rec.data.icon })
      }

      const newRegionMap: RegionMap = new Map()
      const newRegionOptions: FilterOption[] = []
      for (const rec of regionsRes.data as unknown as RegionRecord[]) {
        newRegionMap.set(rec.id, rec.data)
        newRegionOptions.push({ id: rec.id, name: rec.data.name, flag: rec.data.flag_emoji })
      }

      setDeptMap(newDeptMap)
      setRegionMap(newRegionMap)
      setDeptOptions(newDeptOptions)
      setRegionOptions(newRegionOptions)
    }
    loadRefs().catch(console.error)
  }, [])

  const fetchAllTimed = useCallback(
    async (currentPage: number, currentFilters: FilterState, bypassCache = false) => {
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
              ...(Object.keys(where).length ? { where } : {}),
            })
          setSonicMs(Math.round(performance.now() - t0))
          setCacheSource(headers.get('x-cache-source') ?? headers.get('sonicjs-source'))
          setEmployees(response.data as unknown as EmployeeRecord[])
          setPageCount(response.meta.count)
          setHasNextPage(response.meta.count === PAGE_SIZE)
        } catch (err) {
          console.error('SonicJS error:', err)
        } finally {
          setSonicLoading(false)
        }
      })()

      const payloadPromise = (async () => {
        try {
          const { docs, ms } = await fetchPayloadEmployees(currentPage + 1, PAGE_SIZE)
          setPayloadEmployees(docs)
          setPayloadMs(ms)
        } catch (err) {
          console.error('Payload error:', err)
        } finally {
          setPayloadLoading(false)
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

        </div>
      </header>

      {/* ── Filters (horizontal) ── */}
      <div className="border-b border-white/5 bg-slate-950/60 px-4 sm:px-6 lg:px-8 py-3">
        <Filters
          filters={filters}
          deptOptions={deptOptions}
          regionOptions={regionOptions}
          onChange={handleFilterChange}
        />
      </div>

      {/* ── Stats bar ── */}
      <StatsBar sonicMs={sonicMs} payloadMs={payloadMs} sonicSource={cacheSource} />

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

          {/* Divider */}
          <div className="bg-white/5 self-stretch hidden lg:block" />

          {/* Payload side */}
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
      </div>
    </div>
  )
}
