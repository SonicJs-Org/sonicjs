/**
 * Demo seed content.
 *
 * Sample documents for each demo collection. Pure data — no timestamps via
 * Date.now() so the seed stays deterministic; `publishedAt` uses fixed ISO
 * strings. Image fields reference the derived public URLs of the seeded
 * media assets (see assets/images.ts).
 */

import { mediaUrl } from './assets/images'

export interface SeedItem {
  slug: string
  title: string
  data: Record<string, unknown>
}

export interface SeedCollection {
  typeId: string
  items: SeedItem[]
}

const blogPosts: SeedItem[] = [
  {
    slug: 'getting-started-with-sonicjs',
    title: 'Getting Started with SonicJS',
    data: {
      title: 'Getting Started with SonicJS',
      slug: 'getting-started-with-sonicjs',
      excerpt: 'Spin up a Cloudflare-native headless CMS in minutes.',
      content:
        '<p>SonicJS runs entirely on the Cloudflare developer platform — Workers, D1, R2, and KV. ' +
        'This guide walks you through your first collection and your first published document.</p>' +
        '<p>Everything you see on this demo site is seeded automatically and resets every two hours.</p>',
      author: 'SonicJS Team',
      heroImage: mediaUrl('blog-getting-started.svg'),
      category: 'tutorial',
      publishedAt: '2026-01-15T09:00:00.000Z',
      featured: true,
    },
  },
  {
    slug: 'why-edge-first-content',
    title: 'Why Edge-First Content Wins',
    data: {
      title: 'Why Edge-First Content Wins',
      slug: 'why-edge-first-content',
      excerpt: 'Serving content from 300+ locations changes what is possible.',
      content:
        '<p>When your CMS lives at the edge, every read is milliseconds from the visitor. ' +
        'No origin round-trips, no cold regional databases — just fast, cached documents.</p>',
      author: 'Marcus Chen',
      heroImage: mediaUrl('blog-edge-first.svg'),
      category: 'engineering',
      publishedAt: '2026-02-03T14:30:00.000Z',
      featured: true,
    },
  },
  {
    slug: 'inside-the-document-model',
    title: 'Inside the SonicJS Document Model',
    data: {
      title: 'Inside the SonicJS Document Model',
      slug: 'inside-the-document-model',
      excerpt: 'One unified repository for every content type, version, and reference.',
      content:
        '<p>Instead of a table per feature, SonicJS stores everything as documents. ' +
        'Versions, references, and per-document permissions all live in one place, ' +
        'queryable through generated columns and facets.</p>',
      author: 'Amara Okafor',
      heroImage: mediaUrl('blog-document-model.svg'),
      category: 'product',
      publishedAt: '2026-02-20T11:15:00.000Z',
      featured: false,
    },
  },
]

const pages: SeedItem[] = [
  {
    slug: 'home',
    title: 'Home',
    data: {
      title: 'Build at the Edge',
      slug: 'home',
      body:
        '<h1>Build at the Edge</h1>' +
        '<p>SonicJS is a Cloudflare-native headless CMS. This is a live demo — feel free to ' +
        'explore the admin, edit content, and upload media. Everything resets every two hours.</p>',
      heroImage: mediaUrl('page-home.svg'),
      showInNav: true,
      navOrder: 1,
    },
  },
  {
    slug: 'about',
    title: 'About',
    data: {
      title: 'About This Demo',
      slug: 'about',
      body:
        '<h1>About This Demo</h1>' +
        '<p>demo.sonicjs.com always runs the latest version from the main branch. ' +
        'Log in with the prefilled demo credentials to see the full admin experience.</p>',
      showInNav: true,
      navOrder: 2,
    },
  },
  {
    slug: 'contact',
    title: 'Contact',
    data: {
      title: 'Contact',
      slug: 'contact',
      body:
        '<h1>Contact</h1>' +
        '<p>Questions about SonicJS? Visit the docs or join the community on GitHub and Discord.</p>',
      showInNav: true,
      navOrder: 3,
    },
  },
]

const testimonials: SeedItem[] = [
  {
    slug: 'jane-rivera',
    title: 'Jane Rivera',
    data: {
      name: 'Jane Rivera',
      role: 'CTO',
      company: 'Northwind Labs',
      quote: 'SonicJS let us ship a global content platform without standing up a single server.',
      avatar: mediaUrl('avatar-jane.svg'),
      rating: 5,
      featured: true,
    },
  },
  {
    slug: 'marcus-chen',
    title: 'Marcus Chen',
    data: {
      name: 'Marcus Chen',
      role: 'Lead Engineer',
      company: 'Pixelforge',
      quote: 'The document model is the cleanest content architecture I have worked with.',
      avatar: mediaUrl('avatar-marcus.svg'),
      rating: 5,
      featured: true,
    },
  },
  {
    slug: 'amara-okafor',
    title: 'Amara Okafor',
    data: {
      name: 'Amara Okafor',
      role: 'Product Manager',
      company: 'Brightwave',
      quote: 'Our editors love how fast the admin feels, and our developers love the API.',
      avatar: mediaUrl('avatar-amara.svg'),
      rating: 4,
      featured: false,
    },
  },
]

const faqs: SeedItem[] = [
  {
    slug: 'what-is-sonicjs',
    title: 'What is SonicJS?',
    data: {
      question: 'What is SonicJS?',
      answer: '<p>SonicJS is an open-source, Cloudflare-native headless CMS built on Hono, Workers, and D1.</p>',
      category: 'general',
      order: 1,
    },
  },
  {
    slug: 'how-much-does-it-cost',
    title: 'How much does it cost?',
    data: {
      question: 'How much does it cost?',
      answer: '<p>SonicJS is free and open source. You only pay for the Cloudflare resources you use.</p>',
      category: 'billing',
      order: 2,
    },
  },
  {
    slug: 'what-database-does-it-use',
    title: 'What database does it use?',
    data: {
      question: 'What database does it use?',
      answer: '<p>Cloudflare D1 (SQLite) with a unified document repository for all content.</p>',
      category: 'technical',
      order: 3,
    },
  },
  {
    slug: 'are-the-demo-credentials-real',
    title: 'Are the demo credentials real?',
    data: {
      question: 'Are the demo credentials real?',
      answer: '<p>Yes — this demo prefills admin@sonicjs.com / sonicjs!. All data resets every two hours.</p>',
      category: 'account',
      order: 4,
    },
  },
]

export const SEED_COLLECTIONS: SeedCollection[] = [
  { typeId: 'blog_post', items: blogPosts },
  { typeId: 'page', items: pages },
  { typeId: 'testimonial', items: testimonials },
  { typeId: 'faq', items: faqs },
]
