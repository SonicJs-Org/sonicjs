// Module-level flag set by demoLoginPlugin.onBoot(). Per-isolate, resets on cold start
// (which is fine — onBoot always runs before any request in this isolate).
let _demoModeActive = false

export function setDemoModeActive(): void {
  _demoModeActive = true
}

export function isDemoModeActive(): boolean {
  return _demoModeActive
}
