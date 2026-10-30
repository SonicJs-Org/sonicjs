// ── Generic content record shape (from SonicJS content API) ──────────────────

export interface ContentRecord<T> {
  id: string
  title: string
  slug: string
  status: string
  collectionId: string
  data: T
  created_at: number
  updated_at: number
}

// ── Collection data shapes ────────────────────────────────────────────────────

export interface DepartmentData {
  name: string
  description?: string
  icon?: string
  color?: string
}

export interface RegionData {
  name: string
  display_name?: string
  timezone?: string
  flag_emoji?: string
}

export interface EmployeeData {
  first_name: string
  last_name: string
  department: string  // reference ID → departments collection
  job_title: string
  region: string      // reference ID → regions collection
  email: string
  phone: string
  avatar_seed: string
}

// ── Typed records ─────────────────────────────────────────────────────────────

export type EmployeeRecord = ContentRecord<EmployeeData>
export type DepartmentRecord = ContentRecord<DepartmentData>
export type RegionRecord = ContentRecord<RegionData>

// ── Lookup maps (built from fetched dept/region lists) ────────────────────────

export interface DeptMeta {
  name: string
  icon: string
  color: string
  tailwindClass: string
}

export type DeptMap = Map<string, DeptMeta>    // id → meta
export type RegionMap = Map<string, RegionData>  // id → data

// ── Filter state — department/region hold IDs (not display names) ─────────────

export interface FilterState {
  department: string  // department record ID, or '' for all
  region: string      // region record ID, or '' for all
}

// ── Filter option (for select dropdowns) ─────────────────────────────────────

export interface FilterOption {
  id: string
  name: string
  icon?: string
  flag?: string
}
