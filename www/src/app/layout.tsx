import { type Metadata } from 'next'
import Script from 'next/script'

import { Providers } from '@/app/providers'
import { Layout } from '@/components/Layout'
import { type Section } from '@/components/SectionProvider'

import '@/styles/tailwind.css'
import allSections from './allSections.json'

export const metadata: Metadata = {
  metadataBase: new URL('https://sonicjs.com'),
  title: {
    template: '%s | SonicJS Docs',
    default: 'SonicJS - Modern Headless CMS for Cloudflare Workers',
  },
  description:
    'SonicJS is a modern, blazingly fast headless CMS built with TypeScript, Hono, and Cloudflare Workers. Deploy globally with edge performance, D1 database, and R2 storage.',
  keywords: [
    'headless cms',
    'cloudflare workers',
    'typescript cms',
    'edge cms',
    'hono',
    'd1 database',
    'serverless cms',
    'api-first cms',
    'open source cms',
  ],
  authors: [{ name: 'SonicJS Team' }],
  creator: 'SonicJS',
  publisher: 'SonicJS',
  icons: {
    icon: '/favicon.svg',
    apple: '/sonicjs-favicon.png',
  },
  openGraph: {
    type: 'website',
    locale: 'en_US',
    url: 'https://sonicjs.com',
    siteName: 'SonicJS',
    title: 'SonicJS - Modern Headless CMS for Cloudflare Workers',
    description:
      'Build blazingly fast content APIs with SonicJS. TypeScript-first headless CMS built for Cloudflare Workers with D1 database and R2 storage.',
    images: [
      {
        url: 'https://sonicjs.com/sonicjs-og.png',
        width: 1792,
        height: 1024,
        alt: 'SonicJS - Modern Headless CMS for Cloudflare Workers',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'SonicJS - Modern Headless CMS for Cloudflare Workers',
    description:
      'Build blazingly fast content APIs with SonicJS. TypeScript-first headless CMS built for Cloudflare Workers.',
    images: ['https://sonicjs.com/sonicjs-og.png'],
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-video-preview': -1,
      'max-image-preview': 'large',
      'max-snippet': -1,
    },
  },
  alternates: {
    canonical: 'https://sonicjs.com',
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="h-full" suppressHydrationWarning>
      <head>
        <Script
          src="https://www.googletagmanager.com/gtag/js?id=G-FWS35H2E1W"
          strategy="afterInteractive"
        />
        <Script id="google-analytics" strategy="afterInteractive">
          {`
            window.dataLayer = window.dataLayer || [];
            function gtag(){dataLayer.push(arguments);}
            gtag('js', new Date());
            gtag('config', 'G-FWS35H2E1W');
          `}
        </Script>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{
            __html: JSON.stringify({
              '@context': 'https://schema.org',
              '@graph': [
                {
                  '@type': 'Organization',
                  '@id': 'https://sonicjs.com/#organization',
                  name: 'SonicJS',
                  url: 'https://sonicjs.com',
                  logo: {
                    '@type': 'ImageObject',
                    url: 'https://sonicjs.com/sonicjs-favicon.png',
                  },
                  sameAs: [
                    'https://github.com/lane711/sonicjs',
                    'https://twitter.com/nicholasbarger',
                    'https://discord.gg/SV4Mqsss8f',
                  ],
                },
                {
                  '@type': 'SoftwareApplication',
                  '@id': 'https://sonicjs.com/#software',
                  name: 'SonicJS',
                  description:
                    'A modern, blazingly fast headless CMS built with TypeScript, Hono, and Cloudflare Workers.',
                  applicationCategory: 'DeveloperApplication',
                  operatingSystem: 'Cross-platform',
                  offers: {
                    '@type': 'Offer',
                    price: '0',
                    priceCurrency: 'USD',
                  },
                  author: {
                    '@id': 'https://sonicjs.com/#organization',
                  },
                  programmingLanguage: 'TypeScript',
                  runtimePlatform: 'Cloudflare Workers',
                },
                {
                  '@type': 'WebSite',
                  '@id': 'https://sonicjs.com/#website',
                  url: 'https://sonicjs.com',
                  name: 'SonicJS Documentation',
                  publisher: {
                    '@id': 'https://sonicjs.com/#organization',
                  },
                  potentialAction: {
                    '@type': 'SearchAction',
                    target: {
                      '@type': 'EntryPoint',
                      urlTemplate: 'https://sonicjs.com/?q={search_term_string}',
                    },
                    'query-input': 'required name=search_term_string',
                  },
                },
              ],
            }),
          }}
        />
      </head>
      <body className="flex min-h-full bg-white antialiased dark:bg-zinc-900">
        <Providers>
          <div className="w-full">
            <Layout allSections={allSections as Record<string, Array<Section>>}>{children}</Layout>
          </div>
        </Providers>
      </body>
    </html>
  )
}
