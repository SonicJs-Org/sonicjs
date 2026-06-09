// JSON-LD structured data for the /compare page.
// The FAQ entries below MUST stay in sync with the visible FAQ section in
// page.mdx — Google requires FAQPage markup to match on-page content.

const FAQ: { q: string; a: string }[] = [
  {
    q: 'Is SonicJS a good alternative to Strapi, Payload, or Directus?',
    a: 'SonicJS is a strong fit when you want an edge-native CMS on Cloudflare Workers with near-zero cold starts and no feature paywalls. The Node.js incumbents (Payload, Strapi, Directus) are more mature and still lead in areas like GraphQL, internationalization, real-time, and database flexibility — several of which are on the SonicJS roadmap. Pick based on whether edge performance or breadth of features matters more for your project.',
  },
  {
    q: 'Which headless CMS is the fastest?',
    a: 'Architecturally, SonicJS has the lowest cold start (0–5 ms) because it runs on Cloudflare Workers at the edge rather than a single-region Node.js server, so reads are served close to users worldwide. Payload, Strapi, and Directus performance depends on your hosting and caching setup. Real-world numbers vary by workload, so benchmark for your own use case.',
  },
  {
    q: 'Which of these headless CMSs are free and open source?',
    a: 'SonicJS, Payload, Strapi, and Directus are all self-hostable. SonicJS and Payload are MIT licensed. Strapi’s Community edition is MIT but gates features like version history, scheduled publishing, Live Preview, audit logs, advanced RBAC, and SSO behind paid tiers. Directus uses the source-available MSCL license (free under $5M revenue). Sanity and Contentful are hosted SaaS — only Sanity’s Studio editor is open source; their content backends are proprietary and cannot be self-hosted, and Contentful is fully closed-source.',
  },
  {
    q: 'Does SonicJS support GraphQL and internationalization (i18n)?',
    a: 'Not yet — GraphQL and i18n are on the SonicJS roadmap. Today SonicJS ships a REST API with an OpenAPI spec. Payload, Strapi, and Directus all offer GraphQL and i18n today (Directus also offers GraphQL subscriptions and real-time over WebSockets).',
  },
  {
    q: 'Which headless CMS should I choose?',
    a: 'Choose SonicJS for global edge performance on Cloudflare with everything in the free core. Choose Payload for a Next.js-native, deeply typed developer experience. Choose Strapi for the largest plugin ecosystem and a mature admin. Choose Directus to layer a CMS and visual automation onto an existing SQL database. Choose Sanity for real-time multiplayer editing and the GROQ query language, or Contentful for an enterprise-grade composable platform you don’t have to operate. The feature matrix on this page breaks down all six across 125+ capabilities.',
  },
]

export function CompareStructuredData() {
  const breadcrumb = {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: [
      { '@type': 'ListItem', position: 1, name: 'Home', item: 'https://sonicjs.com' },
      { '@type': 'ListItem', position: 2, name: 'Compare', item: 'https://sonicjs.com/compare' },
    ],
  }

  const faqPage = {
    '@context': 'https://schema.org',
    '@type': 'FAQPage',
    mainEntity: FAQ.map(({ q, a }) => ({
      '@type': 'Question',
      name: q,
      acceptedAnswer: { '@type': 'Answer', text: a },
    })),
  }

  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(breadcrumb) }}
      />
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(faqPage) }}
      />
    </>
  )
}
