import type { EmployeeRecord, DeptMap, RegionMap } from '../types'

interface Props {
  employee: EmployeeRecord
  deptMap: DeptMap
  regionMap: RegionMap
}

export function EmployeeCard({ employee, deptMap, regionMap }: Props) {
  const { data: e } = employee
  const avatarUrl = `https://robohash.org/${encodeURIComponent(e.avatar_seed)}?set=set4&size=80x80`
  const dept = deptMap.get(e.department)
  const region = regionMap.get(e.region)

  return (
    <div className="bg-slate-900 border border-white/10 rounded-xl p-4 hover:border-white/20 hover:bg-slate-800/80 transition-all duration-200 group">
      <div className="flex items-start gap-3">
        <img
          src={avatarUrl}
          alt={`${e.first_name} ${e.last_name}`}
          className="w-12 h-12 rounded-full bg-slate-800 flex-shrink-0 border border-white/10"
          loading="lazy"
        />
        <div className="min-w-0 flex-1">
          <p className="font-semibold text-white text-sm truncate">{e.first_name} {e.last_name}</p>
          <p className="text-slate-400 text-xs truncate mt-0.5">{e.job_title}</p>
          <div className="flex items-center gap-1.5 mt-2 flex-wrap">
            {dept ? (
              <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${dept.tailwindClass}`}>
                {dept.icon} {dept.name}
              </span>
            ) : (
              <span className="text-xs px-2 py-0.5 rounded-full font-medium bg-slate-500/20 text-slate-300">
                {e.department}
              </span>
            )}
            <span className="text-xs text-slate-500">
              {region?.flag_emoji} {region?.name ?? e.region}
            </span>
          </div>
        </div>
      </div>
      <div className="mt-3 pt-3 border-t border-white/5 space-y-1">
        <a
          href={`mailto:${e.email}`}
          className="text-xs text-slate-500 hover:text-emerald-400 transition-colors block truncate"
        >
          {e.email}
        </a>
        <p className="text-xs text-slate-600">{e.phone}</p>
      </div>
    </div>
  )
}
