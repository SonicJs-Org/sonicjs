interface Props {
  ms: number | null
  source: string | null
  edgeMode: boolean
  onToggle: (v: boolean) => void
  onRefresh: () => void
  loading?: boolean
}

const SOURCE_LABEL: Record<string, { label: string; dot: string }> = {
  memory:   { label: 'memory', dot: 'bg-emerald-400' },
  kv:       { label: 'kv',     dot: 'bg-sky-400' },
  database: { label: 'db',     dot: 'bg-slate-400' },
  swr:      { label: 'stale',  dot: 'bg-yellow-400' },
}

export function SpeedBadge({ ms, source, edgeMode, onToggle, onRefresh, loading }: Props) {
  const color = ms === null ? 'text-slate-400' : ms < 50 ? 'text-emerald-400' : ms < 150 ? 'text-yellow-400' : 'text-red-400'
  const src = source ? SOURCE_LABEL[source] : null
  const dotClass = src ? src.dot : (edgeMode ? 'bg-emerald-400' : 'bg-slate-400')

  return (
    <div className="flex items-center gap-3">
      {/* Toggle */}
      <div className="flex items-center gap-1.5 bg-slate-800 rounded-lg p-1">
        <button
          onClick={() => onToggle(true)}
          className={`px-3 py-1 rounded-md text-xs font-medium transition-all ${edgeMode ? 'bg-emerald-500 text-white' : 'text-slate-400 hover:text-white'}`}
        >
          Edge
        </button>
        <button
          onClick={() => onToggle(false)}
          className={`px-3 py-1 rounded-md text-xs font-medium transition-all ${!edgeMode ? 'bg-slate-600 text-white' : 'text-slate-400 hover:text-white'}`}
        >
          Origin
        </button>
      </div>

      {/* Badge + refresh */}
      <div className="flex items-center gap-2 bg-slate-800/80 border border-white/10 rounded-lg px-3 py-1.5">
        <div className={`w-1.5 h-1.5 rounded-full ${dotClass} animate-pulse`} />
        <span className={`text-sm font-mono font-bold ${color}`}>
          {ms !== null ? `${ms}ms` : '—'}
        </span>
        <span className="text-slate-500 text-xs">
          {src ? src.label : (edgeMode ? 'edge' : 'origin')}
        </span>
        <button
          onClick={onRefresh}
          disabled={loading}
          title="Refresh"
          className="ml-1 text-slate-400 hover:text-white transition-colors disabled:opacity-40"
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 16 16"
            fill="currentColor"
            className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`}
          >
            <path fillRule="evenodd" d="M13.836 2.477a.75.75 0 0 1 .75.75v3.182a.75.75 0 0 1-.75.75h-3.182a.75.75 0 0 1 0-1.5h1.37l-.84-.841a4.5 4.5 0 0 0-7.08.932.75.75 0 0 1-1.3-.75 6 6 0 0 1 9.44-1.242l.842.84V3.227a.75.75 0 0 1 .75-.75Zm-.911 7.5A.75.75 0 0 1 13.199 11a6 6 0 0 1-9.44 1.241l-.84-.84v1.371a.75.75 0 0 1-1.5 0V9.591a.75.75 0 0 1 .75-.75H5.35a.75.75 0 0 1 0 1.5H3.98l.841.841a4.5 4.5 0 0 0 7.08-.932.75.75 0 0 1 1.025-.273Z" clipRule="evenodd" />
          </svg>
        </button>
      </div>
    </div>
  )
}
