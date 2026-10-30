import { useState, useEffect, useCallback } from 'react'
import { sonic, sonicOrigin, useMock } from './lib/client'
import { toggleEdgeMode } from './lib/mock-data'
import type {
  EmployeeRecord, DepartmentRecord, RegionRecord,
  DeptMap, RegionMap, FilterOption, FilterState,
} from './types'
import { EmployeeGrid } from './components/EmployeeGrid'
import { Filters } from './components/Filters'
import { Pagination } from './components/Pagination'
import { SpeedBadge } from './components/SpeedBadge'
import { CodeSnippet } from './components/CodeSnippet'

const PAGE_SIZE = 18

// Dept name → Tailwind badge class
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

export function App() {
  const [employees, setEmployees] = useState<EmployeeRecord[]>([])
  const [pageCount, setPageCount] = useState(0)
  const [hasNextPage, setHasNextPage] = useState(false)
  const [page, setPage] = useState(0)
  const [loading, setLoading] = useState(false)
  const [responseMs, setResponseMs] = useState<number | null>(null)
  const [cacheSource, setCacheSource] = useState<string | null>(null)
  const [edgeMode, setEdgeMode] = useState(true)
  const [filters, setFilters] = useState<FilterState>({ department: '', region: '' })

  // Reference data — loaded once
  const [deptMap, setDeptMap] = useState<DeptMap>(new Map())
  const [regionMap, setRegionMap] = useState<RegionMap>(new Map())
  const [deptOptions, setDeptOptions] = useState<FilterOption[]>([])
  const [regionOptions, setRegionOptions] = useState<FilterOption[]>([])

  // Load departments + regions in parallel on mount
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

  const handleEdgeToggle = (v: boolean) => {
    setEdgeMode(v)
    if (useMock) toggleEdgeMode(v)
    // useEffect re-runs on edgeMode change and passes !edgeMode as bypassCache
  }

  const fetchEmployees = useCallback(
    async (currentPage: number, currentFilters: FilterState, bypassCache = false) => {
      setLoading(true)
      const where: Record<string, Record<string, string>> = {}
      if (currentFilters.department) where['data.department'] = { equals: currentFilters.department }
      if (currentFilters.region) where['data.region'] = { equals: currentFilters.region }

      const client = (!useMock && bypassCache) ? sonicOrigin : sonic
      const t0 = performance.now()
      try {
        const { data: response, headers } = await client
          .collection('employees')
          .listWithHeaders({
            limit: PAGE_SIZE,
            offset: currentPage * PAGE_SIZE,
            status: 'published',
            ...(Object.keys(where).length ? { where } : {}),
          })

        const rows = response.data as unknown as EmployeeRecord[]
        setResponseMs(Math.round(performance.now() - t0))
        setCacheSource(headers.get('x-cache-source') ?? headers.get('sonicjs-source'))
        setEmployees(rows)
        setPageCount(response.meta.count)
        setHasNextPage(response.meta.count === PAGE_SIZE)
      } catch (err) {
        console.error('SDK error:', err)
      } finally {
        setLoading(false)
      }
    },
    [],
  )

  useEffect(() => {
    fetchEmployees(page, filters, !edgeMode)
  }, [page, filters, edgeMode, fetchEmployees])

  const handleFilterChange = (newFilters: FilterState) => {
    setPage(0)
    setFilters(newFilters)
  }

  // For CodeSnippet: resolve filter IDs back to names for display
  const selectedDeptName = filters.department ? (deptMap.get(filters.department)?.name ?? filters.department) : ''
  const selectedRegionName = filters.region ? (regionMap.get(filters.region)?.name ?? filters.region) : ''

  return (
    <div className="min-h-screen bg-slate-950">
      {/* Header */}
      <header className="border-b border-white/10 bg-slate-950/80 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            <div className="w-8 h-8 bg-emerald-400 rounded-lg flex items-center justify-center flex-shrink-0">
              <span className="text-slate-900 font-bold text-sm">S</span>
            </div>
            <div className="min-w-0">
              <h1 className="text-white font-semibold text-sm sm:text-base leading-tight">
                SonicJS SDK Demo
              </h1>
              <p className="text-slate-500 text-xs hidden sm:block">
                Employee Directory
                {useMock && <span className="ml-1 text-yellow-500/80">· mock data</span>}
              </p>
            </div>
          </div>
          <SpeedBadge ms={responseMs} source={cacheSource} edgeMode={edgeMode} onToggle={handleEdgeToggle} onRefresh={() => fetchEmployees(page, filters, !edgeMode)} loading={loading} />
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-5 grid grid-cols-1 lg:grid-cols-[280px_1fr] gap-5">
        {/* Sidebar */}
        <aside className="space-y-4">
          <Filters
            filters={filters}
            deptOptions={deptOptions}
            regionOptions={regionOptions}
            onChange={handleFilterChange}
          />
          <CodeSnippet
            filters={{ department: selectedDeptName, region: selectedRegionName }}
            page={page}
            pageSize={PAGE_SIZE}
          />
        </aside>

        {/* Main content */}
        <main>
          <EmployeeGrid
            employees={employees}
            loading={loading}
            deptMap={deptMap}
            regionMap={regionMap}
          />
          {(page > 0 || hasNextPage) && (
            <Pagination
              page={page}
              pageSize={PAGE_SIZE}
              count={pageCount}
              hasNext={hasNextPage}
              onPrev={() => setPage((p) => p - 1)}
              onNext={() => setPage((p) => p + 1)}
            />
          )}
        </main>
      </div>
    </div>
  )
}
