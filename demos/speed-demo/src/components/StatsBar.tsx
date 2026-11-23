const ORIGIN_MS = 1429

interface StatsBarProps {
  ms: number | null
}

export function StatsBar({ ms }: StatsBarProps) {
  const boost = ms ? (ORIGIN_MS / ms).toFixed(1) + 'x' : '--'
  const sonicDisplay = ms ? `${ms}ms` : '--'

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-4">
      <dl className="grid grid-cols-3 gap-3">
        {/* Origin */}
        <div className="bg-slate-900 border border-white/10 rounded-xl p-4 sm:p-6 text-center">
          <dd className="text-2xl sm:text-3xl font-semibold tracking-tight text-white">
            {ORIGIN_MS}ms
          </dd>
          <dt className="mt-2">
            <span className="inline-flex items-center rounded-full bg-red-500/10 px-3 py-1 text-xs font-medium text-red-400 ring-1 ring-inset ring-red-500/20">
              Origin
            </span>
          </dt>
        </div>

        {/* SonicJS */}
        <div className="bg-slate-900 border border-white/10 rounded-xl p-4 sm:p-6 text-center">
          <dd className="text-2xl sm:text-3xl font-semibold tracking-tight text-white">
            {sonicDisplay}
          </dd>
          <dt className="mt-2">
            <span className="inline-flex items-center rounded-full bg-blue-500/10 px-3 py-1 text-xs font-medium text-blue-400 ring-1 ring-inset ring-blue-500/20">
              SonicJS
            </span>
          </dt>
        </div>

        {/* Boost */}
        <div className="bg-slate-900 border border-white/10 rounded-xl p-4 sm:p-6 text-center">
          <dd className="text-2xl sm:text-3xl font-semibold tracking-tight text-white">
            {boost}
          </dd>
          <dt className="mt-2">
            <span className="inline-flex items-center rounded-full bg-green-500/10 px-3 py-1 text-xs font-medium text-green-400 ring-1 ring-inset ring-green-500/20">
              Boost
            </span>
          </dt>
        </div>
      </dl>
    </div>
  )
}
