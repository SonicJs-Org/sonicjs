import type { Reporter, FullResult, FullConfig } from '@playwright/test/reporter'
import { sanitizeURL, writeInvocationManifest, type ReportingOptions } from './options'

/** Metadata only: official and native reporters retain ownership of results. */
export default class InvocationReporter implements Reporter {
  private options: ReportingOptions
  constructor({ reporting }: { reporting: ReportingOptions }) { this.options = reporting }
  private record(outcome?: 'passed' | 'failed' | 'interrupted') {
    writeInvocationManifest(this.options, outcome ? { outcome } : undefined)
  }
  onBegin(config: FullConfig) {
    this.options.manifest.startedAt = new Date().toISOString()
    this.options.manifest.targetURL = sanitizeURL(config.projects[0]?.use.baseURL)
    if (this.options.notice) console.log(this.options.notice)
    this.record()
  }
  onEnd(result: FullResult) { this.record(result.status === 'passed' ? 'passed' : result.status === 'interrupted' ? 'interrupted' : 'failed') }
}
