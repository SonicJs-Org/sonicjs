interface StatsBarProps {
  sonicMs: number | null
  payloadMs: number | null
  sonicSource: string | null
}

const SOURCE_LABEL: Record<string, string> = {
  memory: 'memory cache',
  kv: 'KV cache',
  database: 'D1 database',
  swr: 'stale-while-revalidate',
}

export function StatsBar({ sonicMs, payloadMs, sonicSource }: StatsBarProps) {
  const maxMs = Math.max(sonicMs ?? 0, payloadMs ?? 0, 400)

  const sonicPct = sonicMs !== null ? Math.max((sonicMs / maxMs) * 100, 2) : 0
  const payloadPct = payloadMs !== null ? Math.max((payloadMs / maxMs) * 100, 2) : 0

  const boost =
    sonicMs && payloadMs ? `${(payloadMs / sonicMs).toFixed(1)}×` : '—'

  const sonicColor =
    sonicMs === null ? 'text-slate-400'
    : sonicMs < 50 ? 'text-emerald-400'
    : sonicMs < 200 ? 'text-yellow-400'
    : 'text-red-400'

  const payloadColor =
    payloadMs === null ? 'text-slate-400'
    : payloadMs < 300 ? 'text-yellow-400'
    : 'text-red-400'

  const sourceLabel = sonicSource ? (SOURCE_LABEL[sonicSource] ?? sonicSource) : 'edge'

  const Dots = ({ color }: { color: string }) => (
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

  return (
    <div className="border-b border-white/10 bg-slate-900/50">
      <div className="px-4 sm:px-6 lg:px-8 py-4">
        <div className="grid grid-cols-3 gap-4">

          {/* SonicJS */}
          <div className="bg-slate-900 border border-emerald-500/20 rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <span className="text-emerald-400 text-sm">⚡</span>
                <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">SonicJS Edge</span>
              </div>
              {sonicSource && (
                <span className="text-xs text-emerald-500/70 bg-emerald-500/10 px-2 py-0.5 rounded-full">
                  {sourceLabel}
                </span>
              )}
            </div>
            <div className={`text-3xl font-bold font-mono tracking-tight mb-3 ${sonicColor}`}>
              {sonicMs !== null ? `${sonicMs}ms` : <Dots color="bg-emerald-400" />}
            </div>
            <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-emerald-400 rounded-full transition-all duration-700 ease-out"
                style={{ width: `${sonicPct}%` }}
              />
            </div>
            <p className="text-xs text-slate-600 mt-1.5">Cloudflare Workers + D1</p>
          </div>

          {/* Payload CMS */}
          <div className="bg-slate-900 border border-orange-500/20 rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <span className="text-orange-400 text-sm">🐢</span>
                <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Payload CMS</span>
              </div>
              <span className="text-xs text-orange-500/70 bg-orange-500/10 px-2 py-0.5 rounded-full">
                CF Workers + PostgreSQL
              </span>
            </div>
            <div className={`text-3xl font-bold font-mono tracking-tight mb-3 ${payloadColor}`}>
              {payloadMs !== null ? `${payloadMs}ms` : <Dots color="bg-orange-400" />}
            </div>
            <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-orange-400 rounded-full transition-all duration-700 ease-out"
                style={{ width: `${payloadPct}%` }}
              />
            </div>
            <p className="text-xs text-slate-600 mt-1.5">Cloudflare Workers + PostgreSQL</p>
          </div>

          {/* Boost */}
          <div className="bg-slate-900 border border-white/10 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-3">
              <span className="text-sm">🏆</span>
              <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Speed Boost</span>
            </div>
            <div className="text-3xl font-bold font-mono tracking-tight mb-3 text-white">
              {boost}
            </div>
            <div className="space-y-1.5">
              <div className="flex items-center gap-2 text-xs">
                <div className="w-2 h-2 bg-emerald-400 rounded-full flex-shrink-0" />
                <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-emerald-400 rounded-full transition-all duration-700 ease-out" style={{ width: `${sonicPct}%` }} />
                </div>
                <span className="text-slate-500 w-14 text-right">{sonicMs !== null ? `${sonicMs}ms` : '…'}</span>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <div className="w-2 h-2 bg-orange-400 rounded-full flex-shrink-0" />
                <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-orange-400 rounded-full transition-all duration-700 ease-out" style={{ width: `${payloadPct}%` }} />
                </div>
                <span className="text-slate-500 w-14 text-right">{payloadMs !== null ? `${payloadMs}ms` : '…'}</span>
              </div>
            </div>
            <p className="text-xs text-slate-600 mt-2">SonicJS is faster</p>
          </div>

        </div>
      </div>
    </div>
  )
}
