import type { PayloadEmployee } from '../types'

interface Props {
  employee: PayloadEmployee
  loading?: false
}

interface SkeletonProps {
  loading: true
}

export function PayloadCard(props: Props | SkeletonProps) {
  if ('loading' in props && props.loading) {
    return (
      <div className="bg-slate-900 border border-orange-500/10 rounded-xl p-4 animate-pulse">
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

  const { employee: e } = props as Props
  const avatarUrl = `https://robohash.org/${encodeURIComponent(e.avatarSeed)}?set=set4&size=80x80`

  // Convert hex color to rgba for badge background
  const hexToRgba = (hex: string, alpha: number) => {
    const r = parseInt(hex.slice(1, 3), 16)
    const g = parseInt(hex.slice(3, 5), 16)
    const b = parseInt(hex.slice(5, 7), 16)
    return `rgba(${r},${g},${b},${alpha})`
  }

  const deptBg = e.department?.color ? hexToRgba(e.department.color, 0.15) : 'rgba(100,116,139,0.15)'
  const deptColor = e.department?.color ?? '#94a3b8'

  return (
    <div className="bg-slate-900 border border-orange-500/15 rounded-xl p-4 hover:border-orange-500/35 hover:bg-slate-800/80 transition-all duration-200">
      <div className="flex items-start gap-3">
        <img
          src={avatarUrl}
          alt={`${e.firstName} ${e.lastName}`}
          className="w-12 h-12 rounded-full bg-slate-800 flex-shrink-0 border border-orange-500/20"
          loading="lazy"
        />
        <div className="min-w-0 flex-1">
          <p className="font-semibold text-white text-sm truncate">{e.firstName} {e.lastName}</p>
          <p className="text-slate-400 text-xs truncate mt-0.5">{e.jobTitle}</p>
          <div className="flex items-center gap-1.5 mt-2 flex-wrap">
            {e.department && (
              <span
                className="text-xs px-2 py-0.5 rounded-full font-medium"
                style={{ background: deptBg, color: deptColor }}
              >
                {e.department.icon} {e.department.name}
              </span>
            )}
            {e.region && (
              <span className="text-xs text-slate-500">
                {e.region.flagEmoji} {e.region.name}
              </span>
            )}
          </div>
        </div>
      </div>
      <div className="mt-3 pt-3 border-t border-orange-500/5 space-y-1">
        <a
          href={`mailto:${e.email}`}
          className="text-xs text-slate-500 hover:text-orange-400 transition-colors block truncate"
        >
          {e.email}
        </a>
        <p className="text-xs text-slate-600">{e.phone}</p>
      </div>
    </div>
  )
}
