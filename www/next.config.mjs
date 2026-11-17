import nextMDX from '@next/mdx'
import path from 'path'
import { fileURLToPath } from 'url'

import { recmaPlugins } from './src/mdx/recma.mjs'
import { rehypePlugins } from './src/mdx/rehype.mjs'
import { remarkPlugins } from './src/mdx/remark.mjs'
import withSearch from './src/mdx/search.mjs'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

const withMDX = nextMDX({
  options: {
    remarkPlugins,
    rehypePlugins,
    recmaPlugins,
  },
})

/** @type {import('next').NextConfig} */
const nextConfig = {
  pageExtensions: ['js', 'jsx', 'ts', 'tsx', 'mdx'],
  outputFileTracingRoot: path.join(__dirname, '..'),
  outputFileTracingIncludes: {
    '/**/*': ['./src/app/**/*.mdx', './content/blog/**/*.mdx'],
  },
  // worker-mailer statically imports `cloudflare:sockets`, which only
  // resolves inside workerd. Keeping it out of Next's webpack bundle (as a
  // real unbundled require/import) lets OpenNext's own ESM bundler hand the
  // cloudflare: import to wrangler/workerd correctly at the final build step.
  serverExternalPackages: ['worker-mailer'],
}

export default withSearch(withMDX(nextConfig))

// Expose Cloudflare bindings (EMAIL, vars, secrets) to `next dev` via getCloudflareContext().
// Without this, bindings are only present in `opennextjs-cloudflare preview`/`deploy`.
import { initOpenNextCloudflareForDev } from '@opennextjs/cloudflare'
initOpenNextCloudflareForDev()
