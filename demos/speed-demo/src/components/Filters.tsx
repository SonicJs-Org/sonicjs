import type { FilterState, FilterOption } from '../types'

interface Props {
  filters: FilterState
  deptOptions: FilterOption[]
  regionOptions: FilterOption[]
  onChange: (f: FilterState) => void
}

function FilterGroup({ label, options, active, onSelect, renderLabel }: {
  label: string
  options: FilterOption[]
  active: string
  onSelect: (id: string) => void
  renderLabel: (o: FilterOption) => string
}) {
  return (
    <div>
      <p className="text-xs text-slate-400 mb-2 uppercase tracking-wider">{label}</p>
      <div className="flex flex-wrap gap-1.5">
        <button
          onClick={() => onSelect('')}
          className={`px-2.5 py-1 rounded-md text-xs font-medium transition-all ${
            active === ''
              ? 'bg-emerald-500 text-white'
              : 'bg-slate-800 text-slate-300 hover:bg-slate-700 hover:text-white'
          }`}
        >
          All
        </button>
        {options.map((o) => (
          <button
            key={o.id}
            onClick={() => onSelect(active === o.id ? '' : o.id)}
            className={`px-2.5 py-1 rounded-md text-xs font-medium transition-all ${
              active === o.id
                ? 'bg-emerald-500 text-white'
                : 'bg-slate-800 text-slate-300 hover:bg-slate-700 hover:text-white'
            }`}
          >
            {renderLabel(o)}
          </button>
        ))}
      </div>
    </div>
  )
}

export function Filters({ filters, deptOptions, regionOptions, onChange }: Props) {
  return (
    <div className="bg-slate-900 border border-white/10 rounded-xl p-4 space-y-4">
      <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Filters</h2>

      <FilterGroup
        label="Department"
        options={deptOptions}
        active={filters.department}
        onSelect={(id) => onChange({ ...filters, department: id })}
        renderLabel={(o) => `${o.icon ? o.icon + ' ' : ''}${o.name}`}
      />

      <FilterGroup
        label="Region"
        options={regionOptions}
        active={filters.region}
        onSelect={(id) => onChange({ ...filters, region: id })}
        renderLabel={(o) => `${o.flag ? o.flag + ' ' : ''}${o.name}`}
      />

      {(filters.department || filters.region) && (
        <button
          onClick={() => onChange({ department: '', region: '' })}
          className="w-full text-xs text-slate-400 hover:text-white border border-white/10 rounded-lg py-1.5 transition-colors"
        >
          Clear filters
        </button>
      )}
    </div>
  )
}
