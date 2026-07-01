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
