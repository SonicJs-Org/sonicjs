interface StatsBarProps {
  sonicMs: number | null
  payloadMs: number | null
  sonicSource: string | null
}

export function StatsBar({ sonicMs, payloadMs }: StatsBarProps) {
  const maxMs = Math.max(sonicMs ?? 0, payloadMs ?? 0, 400)

  const sonicPct = sonicMs !== null ? Math.max((sonicMs / maxMs) * 100, 2) : 0
  const payloadPct = payloadMs !== null ? Math.max((payloadMs / maxMs) * 100, 2) : 0

  const boost =
    sonicMs && payloadMs ? `${(payloadMs / sonicMs).toFixed(1)}×` : '—'

  return (
    <div className="border-b border-white/10 bg-slate-900/50">
      <div className="px-4 sm:px-6 lg:px-8 py-4">
        <div className="max-w-xs">
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
