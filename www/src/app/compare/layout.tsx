import { Metadata } from 'next'
import { CompareStructuredData } from './structured-data'

export const metadata: Metadata = {
  title: 'Headless CMS Comparison: SonicJS vs Payload, Strapi, Directus, Sanity & Contentful',
  description:
    'A side-by-side comparison of SonicJS, Payload, Strapi, Directus, Sanity, and Contentful across 125+ features — architecture, pricing, content modeling, APIs, auth, media, i18n, and performance. See how an edge-native CMS stacks up against the Node.js and SaaS incumbents.',
  keywords: [
    'sonicjs vs strapi',
    'sonicjs vs payload',
    'sonicjs vs directus',
    'sonicjs vs sanity',
    'sonicjs vs contentful',
    'payload vs strapi',
    'strapi vs directus',
    'sanity vs contentful',
    'headless cms comparison',
    'best headless cms 2026',
    'strapi alternative',
    'payload cms alternative',
    'directus alternative',
    'contentful alternative',
    'sanity alternative',
    'edge headless cms',
    'open source cms comparison',
  ],
  alternates: {
    canonical: '/compare',
  },
  openGraph: {
    title: 'SonicJS vs Payload, Strapi, Directus, Sanity & Contentful',
    description:
      'Side-by-side headless CMS comparison: 125 features across architecture, pricing, APIs, auth, and performance.',
    url: '/compare',
    type: 'article',
    images: [
      {
        url: '/sonicjs-og.png',
        width: 1792,
        height: 1024,
        alt: 'SonicJS vs Payload vs Strapi vs Directus comparison',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'SonicJS vs Payload, Strapi, Directus, Sanity & Contentful',
    description:
      'Side-by-side headless CMS comparison: 125 features across architecture, pricing, APIs, auth, and performance.',
    images: ['/sonicjs-og.png'],
  },
}

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <CompareStructuredData />
      {children}
    </>
  )
}
