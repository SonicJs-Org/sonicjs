interface Props {
  page: number
  pageSize: number
  count: number
  hasNext: boolean
  onPrev: () => void
  onNext: () => void
}

export function Pagination({ page, pageSize, count, hasNext, onPrev, onNext }: Props) {
  const from = page * pageSize + 1
  const to = page * pageSize + count
  return (
    <div className="mt-6 flex items-center justify-between border-t border-white/10 pt-4">
      <span className="text-slate-400 text-sm">
        Showing {from}–{to} · Page {page + 1}
      </span>
      <div className="flex gap-2">
        <button
          onClick={onPrev}
          disabled={page === 0}
          className="px-4 py-2 text-sm bg-slate-800 border border-white/10 rounded-lg disabled:opacity-30 hover:bg-slate-700 transition-colors disabled:cursor-not-allowed"
        >
          ← Prev
        </button>
        <button
          onClick={onNext}
          disabled={!hasNext}
          className="px-4 py-2 text-sm bg-slate-800 border border-white/10 rounded-lg disabled:opacity-30 hover:bg-slate-700 transition-colors disabled:cursor-not-allowed"
        >
          Next →
        </button>
      </div>
    </div>
  )
}
