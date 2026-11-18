import { defineConfig } from '@playwright/test'
import base from './playwright.config'

// Same contracts, URL, diagnostics and policy as the main suite; only server ownership differs.
export default defineConfig({ ...base, webServer: undefined })
