import { defineConfig } from 'tsup'

export default defineConfig([
  {
    entry: { index: 'src/index.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    sourcemap: true,
    clean: true,
    treeshake: true,
    target: 'es2022',
    external: ['@sonicjs-cms/core'],
  },
  {
    entry: { cli: 'src/codegen/cli.ts' },
    format: ['cjs'],
    dts: false,
    sourcemap: true,
    target: 'es2022',
    external: ['@sonicjs-cms/core'],
    banner: { js: '#!/usr/bin/env node' },
  },
])
