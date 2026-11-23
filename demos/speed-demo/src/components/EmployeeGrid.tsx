import type { EmployeeRecord, DeptMap, RegionMap } from '../types'
import { EmployeeCard } from './EmployeeCard'

interface Props {
  employees: EmployeeRecord[]
  loading: boolean
  deptMap: DeptMap
  regionMap: RegionMap
}

function Skeleton() {
  return (
    <div className="bg-slate-900 border border-white/10 rounded-xl p-4 animate-pulse">
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

export function EmployeeGrid({ employees, loading, deptMap, regionMap }: Props) {
  // Initial load — no prior results to show, use skeletons
  if (loading && employees.length === 0) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
        {Array.from({ length: 18 }, (_, i) => <Skeleton key={i} />)}
      </div>
    )
  }

  if (employees.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-center">
        <p className="text-slate-400 text-lg">No employees found</p>
        <p className="text-slate-600 text-sm mt-1">Try adjusting your filters</p>
      </div>
    )
  }

  return (
    <div
      className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3 transition-opacity duration-150"
      style={{ opacity: loading ? 0.5 : 1 }}
    >
      {employees.map((emp) => (
        <EmployeeCard key={emp.id} employee={emp} deptMap={deptMap} regionMap={regionMap} />
      ))}
    </div>
  )
}
