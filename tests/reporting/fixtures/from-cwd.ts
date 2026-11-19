import { createReportingOptions } from '../options.ts'
console.log(createReportingOptions({ suite: 'core-unit', target: 'none', env: {} }).outputFolder)
