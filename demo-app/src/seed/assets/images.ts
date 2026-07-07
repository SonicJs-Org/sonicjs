/**
 * Demo seed images.
 *
 * Bundled as SVG strings (not binary blobs) so they stay tiny, diff-able, and
 * need no base64 decoding. At reseed time each is encoded to bytes, uploaded to
 * R2 (MEDIA_BUCKET) under the `demo-seed/` prefix, and registered as a
 * media_asset document. Content references them by their derived public URL
 * (`/files/demo-seed/<filename>`), served by the core media route.
 */

/** R2 prefix / media folder for all demo-seeded images. Purged on every reseed. */
export const MEDIA_FOLDER = 'demo-seed'

const r2Key = (filename: string) => `${MEDIA_FOLDER}/${filename}`

/** Public URL the core media route serves the R2 object at. */
export const mediaUrl = (filename: string) => `/files/${r2Key(filename)}`

export interface DemoImage {
  filename: string
  r2Key: string
  svg: string
  mime: string
  width: number
  height: number
  alt: string
}

function banner(title: string, c1: string, c2: string): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="600" viewBox="0 0 1200 600">
  <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="${c1}"/><stop offset="1" stop-color="${c2}"/>
  </linearGradient></defs>
  <rect width="1200" height="600" fill="url(#g)"/>
  <text x="64" y="316" font-family="system-ui, -apple-system, sans-serif" font-size="68" font-weight="700" fill="#ffffff">${title}</text>
  <text x="64" y="384" font-family="system-ui, -apple-system, sans-serif" font-size="28" fill="#ffffff" opacity="0.85">SonicJS Demo</text>
</svg>`
}

function avatar(initials: string, bg: string): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="240" height="240" viewBox="0 0 240 240">
  <rect width="240" height="240" fill="${bg}"/>
  <text x="120" y="120" font-family="system-ui, -apple-system, sans-serif" font-size="96" font-weight="700" fill="#ffffff" text-anchor="middle" dominant-baseline="central">${initials}</text>
</svg>`
}

function img(filename: string, svg: string, width: number, height: number, alt: string): DemoImage {
  return { filename, r2Key: r2Key(filename), svg, mime: 'image/svg+xml', width, height, alt }
}

export const DEMO_IMAGES: DemoImage[] = [
  // Blog hero banners
  img('blog-getting-started.svg', banner('Getting Started', '#6366f1', '#8b5cf6'), 1200, 600, 'Getting started with SonicJS'),
  img('blog-edge-first.svg', banner('Edge-First CMS', '#0ea5e9', '#2563eb'), 1200, 600, 'Edge-first content management'),
  img('blog-document-model.svg', banner('The Document Model', '#10b981', '#0d9488'), 1200, 600, 'The SonicJS document model'),
  // Page hero
  img('page-home.svg', banner('Build at the Edge', '#f59e0b', '#ef4444'), 1200, 600, 'SonicJS home hero'),
  // Testimonial avatars
  img('avatar-jane.svg', avatar('JR', '#6366f1'), 240, 240, 'Avatar for Jane Rivera'),
  img('avatar-marcus.svg', avatar('MC', '#0ea5e9'), 240, 240, 'Avatar for Marcus Chen'),
  img('avatar-amara.svg', avatar('AO', '#10b981'), 240, 240, 'Avatar for Amara Okafor'),
]

/**
 * Static blog hero images from the www marketing site.
 * Uploaded once to R2 under the `blog/` prefix (NOT purged on reseed).
 * Registered as media_asset documents on every reseed (since D1 docs are wiped).
 */
export interface BlogHeroImage {
  slug: string
  r2Key: string
  filename: string
  size: number
  width: number
  height: number
  alt: string
}

const blogHero = (slug: string, size: number, alt: string): BlogHeroImage => ({
  slug,
  r2Key: `blog/${slug}/hero.png`,
  filename: `${slug}-hero.png`,
  size,
  width: slug === 'using-emdash-with-sonicjs' ? 1536 : 1792,
  height: 1024,
  alt,
})

export const BLOG_HERO_IMAGES: BlogHeroImage[] = [
  blogHero('best-open-source-project-for-ai-coding-practice', 4021954, 'Best open source project for AI coding practice'),
  blogHero('building-a-blog-with-sonicjs', 2604450, 'Building a blog with SonicJS'),
  blogHero('building-rest-api-with-sonicjs', 2576722, 'Building a REST API with SonicJS'),
  blogHero('creating-custom-collections-in-sonicjs', 3088447, 'Creating custom collections in SonicJS'),
  blogHero('custom-public-routes-in-sonicjs', 2577213, 'Custom public routes in SonicJS'),
  blogHero('deploy-sonicjs-to-cloudflare-workers', 2144636, 'Deploy SonicJS to Cloudflare Workers'),
  blogHero('directus-vs-payload-vs-sonicjs', 2872910, 'Directus vs Payload vs SonicJS'),
  blogHero('directus-vs-sanity-vs-sonicjs', 3474484, 'Directus vs Sanity vs SonicJS'),
  blogHero('getting-started-with-sonicjs', 2330529, 'Getting started with SonicJS'),
  blogHero('nestjs-vs-sonicjs-vs-hono', 3591775, 'NestJS vs SonicJS vs Hono'),
  blogHero('sanity-vs-contentful-vs-sonicjs', 3119998, 'Sanity vs Contentful vs SonicJS'),
  blogHero('sonicjs-authentication-complete-guide', 2907544, 'SonicJS authentication complete guide'),
  blogHero('sonicjs-caching-strategy', 2428640, 'SonicJS caching strategy'),
  blogHero('sonicjs-d1-database-deep-dive', 2997264, 'SonicJS D1 database deep dive'),
  blogHero('sonicjs-file-uploads-with-r2', 2354505, 'SonicJS file uploads with R2'),
  blogHero('sonicjs-plugin-architecture-deep-dive', 2358528, 'SonicJS plugin architecture deep dive'),
  blogHero('sonicjs-plugins-extending-your-cms', 3250996, 'SonicJS plugins — extending your CMS'),
  blogHero('sonicjs-vs-ghost', 2396152, 'SonicJS vs Ghost'),
  blogHero('sonicjs-vs-strapi', 2224674, 'SonicJS vs Strapi'),
  blogHero('sonicjs-vs-wordpress', 3121720, 'SonicJS vs WordPress'),
  blogHero('strapi-vs-contentful-vs-sonicjs', 2924986, 'Strapi vs Contentful vs SonicJS'),
  blogHero('strapi-vs-directus-vs-sonicjs', 2467750, 'Strapi vs Directus vs SonicJS'),
  blogHero('strapi-vs-payload-vs-sonicjs', 2805602, 'Strapi vs Payload vs SonicJS'),
  blogHero('strapi-vs-sanity-vs-sonicjs', 2340446, 'Strapi vs Sanity vs SonicJS'),
  blogHero('using-emdash-with-sonicjs', 1916519, 'Using em dash with SonicJS'),
  blogHero('using-sonicjs-with-astro', 2093913, 'Using SonicJS with Astro'),
  blogHero('using-sonicjs-with-nextjs', 2456378, 'Using SonicJS with Next.js'),
  blogHero('why-edge-first-cms-is-the-future', 3183607, 'Why edge-first CMS is the future'),
]
