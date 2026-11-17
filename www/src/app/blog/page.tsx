import { Metadata } from 'next'
import { getAllPosts, getFeaturedPosts } from '@/lib/blog'
import { BlogCard } from './components/BlogCard'
import { CategoryFilter } from './components/CategoryFilter'
import { BlogListSchema } from './components/StructuredData'

// Force static generation - required for Cloudflare Workers deployment
export const dynamic = 'force-static'

export const metadata: Metadata = {
  title: 'Blog | SonicJS',
  description:
    'Tutorials, guides, and updates about SonicJS - the edge-first headless CMS for Cloudflare Workers. Learn how to build blazingly fast content APIs.',
  keywords: [
    'sonicjs blog',
    'headless cms tutorials',
    'cloudflare workers guides',
    'edge cms articles',
    'typescript cms tips',
  ],
  openGraph: {
    type: 'website',
    title: 'Blog | SonicJS',
    description:
      'Tutorials, guides, and updates about SonicJS - the edge-first headless CMS for Cloudflare Workers.',
    url: 'https://sonicjs.com/blog',
    siteName: 'SonicJS',
    images: [
      {
        url: 'https://sonicjs.com/sonicjs-og.png',
        width: 1792,
        height: 1024,
        alt: 'SonicJS Blog',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Blog | SonicJS',
    description:
      'Tutorials, guides, and updates about SonicJS - the edge-first headless CMS for Cloudflare Workers.',
    images: ['https://sonicjs.com/sonicjs-og.png'],
  },
  alternates: {
    canonical: 'https://sonicjs.com/blog',
    types: {
      'application/rss+xml': 'https://sonicjs.com/blog/feed.xml',
    },
  },
}

export default async function BlogPage() {
  const posts = await getAllPosts()
  const featuredPosts = await getFeaturedPosts()

  return (
    <>
      <BlogListSchema />
      <div className="mx-auto max-w-7xl px-4 py-16 sm:px-6 lg:px-8">
        {/* Hero Section */}
        <div className="mb-16 text-center">
          <h1 className="text-4xl font-bold tracking-tight text-zinc-900 dark:text-white sm:text-5xl">
            SonicJS Blog
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-lg text-zinc-600 dark:text-zinc-400">
            Tutorials, guides, and updates about edge-first content management with SonicJS and
            Cloudflare Workers.
          </p>
        </div>

        {/* Featured Post */}
        {featuredPosts.length > 0 && (
          <section className="mb-16">
            <h2 className="mb-8 text-2xl font-semibold text-zinc-900 dark:text-white">Featured</h2>
            <div className="max-w-4xl mx-auto">
              <BlogCard key={featuredPosts[0].slug} post={featuredPosts[0]} featured />
            </div>
          </section>
        )}

        {/* Category Filter */}
        <section className="mb-8">
          <CategoryFilter />
        </section>

        {/* All Posts */}
        {posts.length > 0 ? (
          <section>
            <div className="grid gap-8 md:grid-cols-2 lg:grid-cols-3">
              {posts.map((post) => (
                <BlogCard key={post.slug} post={post} />
              ))}
            </div>
          </section>
        ) : (
          <div className="py-16 text-center">
            <p className="text-lg text-zinc-600 dark:text-zinc-400">
              No blog posts yet. Check back soon!
            </p>
          </div>
        )}

        {/* Newsletter CTA */}
        <section className="mt-20 rounded-2xl bg-gradient-to-r from-emerald-500 to-teal-600 p-8 text-center text-white md:p-12">
          <h2 className="text-2xl font-bold md:text-3xl">Stay Updated</h2>
          <p className="mx-auto mt-4 max-w-xl text-emerald-100">
            Get the latest tutorials, guides, and SonicJS updates delivered to your inbox.
          </p>
          <div className="mt-6 flex flex-col items-center justify-center gap-4 sm:flex-row">
            <a
              href="https://github.com/SonicJs-Org/sonicjs"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 rounded-lg bg-white px-6 py-3 font-semibold text-emerald-600 transition-colors hover:bg-emerald-50"
            >
              <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24">
                <path
                  fillRule="evenodd"
                  d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
                  clipRule="evenodd"
                />
              </svg>
              Star on GitHub
            </a>
            <a
              href="https://discord.gg/sonicjs"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 rounded-lg border-2 border-white px-6 py-3 font-semibold text-white transition-colors hover:bg-white/10"
            >
              Join Discord
            </a>
          </div>
        </section>
      </div>
    </>
  )
}
