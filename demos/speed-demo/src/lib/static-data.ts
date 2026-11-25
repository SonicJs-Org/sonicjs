/**
 * Hardcoded department and region reference data.
 * These are fixed seed records — IDs never change — so we skip the
 * two API round-trips (GET /departments + GET /regions) on every load.
 */
import type { DeptMap, RegionMap, FilterOption } from '../types'

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

export const DEPT_MAP: DeptMap = new Map([
  ['dept-engineering', { name: 'Engineering', icon: '🔧', color: '#3B82F6', tailwindClass: DEPT_TAILWIND['Engineering'] }],
  ['dept-product',     { name: 'Product',     icon: '📊', color: '#8B5CF6', tailwindClass: DEPT_TAILWIND['Product']     }],
  ['dept-design',      { name: 'Design',      icon: '🎨', color: '#EC4899', tailwindClass: DEPT_TAILWIND['Design']      }],
  ['dept-marketing',   { name: 'Marketing',   icon: '📣', color: '#F59E0B', tailwindClass: DEPT_TAILWIND['Marketing']   }],
  ['dept-sales',       { name: 'Sales',       icon: '💼', color: '#10B981', tailwindClass: DEPT_TAILWIND['Sales']       }],
  ['dept-hr',          { name: 'HR',          icon: '🤝', color: '#06B6D4', tailwindClass: DEPT_TAILWIND['HR']          }],
  ['dept-finance',     { name: 'Finance',     icon: '💰', color: '#84CC16', tailwindClass: DEPT_TAILWIND['Finance']     }],
  ['dept-legal',       { name: 'Legal',       icon: '⚖️', color: '#6366F1', tailwindClass: DEPT_TAILWIND['Legal']       }],
  ['dept-operations',  { name: 'Operations',  icon: '⚙️', color: '#F97316', tailwindClass: DEPT_TAILWIND['Operations']  }],
])

export const REGION_MAP: RegionMap = new Map([
  ['region-us-east',  { name: 'US-East',  display_name: 'US East Coast',   timezone: 'America/New_York',    flag_emoji: '🇺🇸' }],
  ['region-us-west',  { name: 'US-West',  display_name: 'US West Coast',   timezone: 'America/Los_Angeles', flag_emoji: '🇺🇸' }],
  ['region-eu-west',  { name: 'EU-West',  display_name: 'Western Europe',  timezone: 'Europe/London',       flag_emoji: '🇪🇺' }],
  ['region-eu-north', { name: 'EU-North', display_name: 'Northern Europe', timezone: 'Europe/Stockholm',    flag_emoji: '🇸🇪' }],
  ['region-apac',     { name: 'APAC',     display_name: 'Asia Pacific',    timezone: 'Asia/Singapore',      flag_emoji: '🌏' }],
  ['region-latam',    { name: 'LATAM',    display_name: 'Latin America',   timezone: 'America/Sao_Paulo',   flag_emoji: '🌎' }],
])

export const DEPT_OPTIONS: FilterOption[] = Array.from(DEPT_MAP.entries()).map(
  ([id, meta]) => ({ id, name: meta.name, icon: meta.icon }),
)

export const REGION_OPTIONS: FilterOption[] = Array.from(REGION_MAP.entries()).map(
  ([id, data]) => ({ id, name: data.display_name ?? data.name, flag: data.flag_emoji }),
)
