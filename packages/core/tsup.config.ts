import { defineConfig } from 'tsup'

export default defineConfig({
  // Entry points
  entry: {
    index: 'src/index.ts',
    services: 'src/services/index.ts',
    middleware: 'src/middleware/index.ts',
    routes: 'src/routes/index.ts',
    templates: 'src/templates/index.ts',
    plugins: 'src/plugins/index.ts',
    utils: 'src/utils/index.ts',
    types: 'src/types/index.ts',
    adapters: 'src/adapters/index.ts',
  },

  // Output formats
  format: ['esm', 'cjs'],

  // Generate TypeScript definitions
  dts: true,

  // Code splitting for better tree-shaking
  splitting: true,

  // Generate sourcemaps for debugging
  sourcemap: true,

  // Clean dist folder before build
  clean: true,

  // Don't minify for better debugging (can enable for production)
  minify: false,

  // Tree-shaking
  treeshake: true,

  // External dependencies (not bundled)
  external: [
    '@cloudflare/workers-types',
    'hono',
    'drizzle-orm',
    'zod',
    // Better Auth + cloudflare shim — bundled by wrangler at deploy time, not here
    'better-auth',
    'better-auth-cloudflare',
    '@better-auth/kysely-adapter',
    'kysely',
    // Optional self-host dep — present on Node/Bun, absent on Workers
    'better-sqlite3',
  ],

  // Configure esbuild to drop unused imports
  esbuildOptions(options) {
    options.treeShaking = true
    options.ignoreAnnotations = false
  },

  // Bundle these dependencies (included in package)
  noExternal: [
    'drizzle-zod',
    'marked',
    'highlight.js',
    'semver'
  ],

  // Target environment
  target: 'es2022',
  platform: 'node',

  // Output extension
  outExtension({ format }) {
    return {
      js: format === 'cjs' ? '.cjs' : '.js'
    }
  },

  // TypeScript options
  tsconfig: './tsconfig.json',

  // Suppress chunk output during watch
  silent: true,

  // Build hooks
  onSuccess: async () => {
    const fs = await import('fs')
    const path = await import('path')

    const distDir = path.resolve(process.cwd(), 'dist')

    // Remove bare zod imports from built files
    const indexJs = path.join(distDir, 'index.js')
    const indexCjs = path.join(distDir, 'index.cjs')

    if (fs.existsSync(indexJs)) {
      let content = fs.readFileSync(indexJs, 'utf-8')
      content = content.replace(/^import 'zod';?\n/gm, '')
      fs.writeFileSync(indexJs, content, 'utf-8')
    }

    if (fs.existsSync(indexCjs)) {
      let content = fs.readFileSync(indexCjs, 'utf-8')
      content = content.replace(/^require\(['"]zod['"]\);?\n/gm, '')
      fs.writeFileSync(indexCjs, content, 'utf-8')
    }

    console.log('✓ Build complete!')
  },
})
