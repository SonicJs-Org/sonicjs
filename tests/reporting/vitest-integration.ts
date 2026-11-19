import type { Reporter } from 'vitest/reporters'
import type { TestModule, TestCase, InlineConfig } from 'vitest/node'
import { createReportingOptions, assertUniqueTestNames, writeInvocationManifest, type ReportingSuite } from './options'

/** Independent metadata observer. Vendor owns every report and attempt. */
export function vitestReporting(suite: ReportingSuite): Pick<InlineConfig, 'includeTaskLocation' | 'reporters'> {
  if (process.argv.includes('--list') || process.argv[2] === 'list') return {}
  let options = createReportingOptions({ suite, target: 'none' })
  const vendor = options.vitest.reporters[1]
  let runs = 0
  let active = false
  let rejected = false
  let collected: { project: string; file: string; fullName: string }[] = []
  const record = (outcome?: 'passed' | 'failed' | 'interrupted') => {
    writeInvocationManifest(options, outcome ? { outcome } : undefined)
  }
  const metadata: Reporter = {
    onInit() {
      // Vitest may process.exit(130) before onTestRunEnd. Observe exit only;
      // never intercept signals, alter exit status, or synthesize vendor attempts.
      process.once('exit', code => {
        if (active || (code !== 0 && code !== 130)) record(code === 130 ? 'interrupted' : 'failed')
      })
    },
    onTestRunStart() {
      active = true
      if (runs++) options = createReportingOptions({ suite, target: 'none' })
      options.manifest.startedAt = new Date().toISOString()
      Object.assign(vendor[1], options.vitest.reporters[1][1])
      Object.assign(process.env, options.environment)
      rejected = false
      collected = []
      if (options.notice) console.log(options.notice)
      record()
      console.log(`[flakiness] Report: ${options.outputFolder}`)
    },
    onTestModuleCollected(module: TestModule) {
      try {
        collected.push(...[...module.children.allTests()].map(test => ({
          project: test.project.name || 'vitest', file: module.relativeModuleId,
          fullName: JSON.stringify([...parentNames(test), test.name]),
        })))
        assertUniqueTestNames(collected)
      } catch (error) {
        rejected = true
        // Reject before any upload, even if runner continues finalization after hook error.
        vendor[1].disableUpload = true
        record('failed')
        throw error
      }
    },
    onTestRunEnd(modules, errors, reason) {
      active = false
      record(reason === 'interrupted' ? 'interrupted' : rejected || errors.length || modules.length === 0 || modules.some(m => m.state() === 'failed') ? 'failed' : 'passed')
    },
  }
  // Keep the synchronous start observer before the official reporter: public options
  // must point at this run's folder before the vendor creates its per-run state.
  return { includeTaskLocation: true as const, reporters: ['default', metadata, vendor] }
}

function parentNames(test: TestCase): string[] {
  const names: string[] = []
  for (let parent = test.parent; parent && parent.type !== 'module'; parent = parent.parent) names.unshift(parent.name)
  return names
}
