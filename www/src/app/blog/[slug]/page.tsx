import { Metadata } from 'next'
import { notFound } from 'next/navigation'
import { compileMDX } from 'next-mdx-remote/rsc'
import remarkGfm from 'remark-gfm'
import { getPost, getAllPosts, getRelatedPosts } from '@/lib/blog'
import { BlogHeader } from '../components/BlogHeader'
import { ShareButtons } from '../components/ShareButtons'
import { RelatedPosts } from '../components/RelatedPosts'
import { BlogPostSchema, BreadcrumbSchema } from '../components/StructuredData'
import { TLDRBox } from '../components/TLDRBox'
import { Callout } from '@/components/Callout'

// Force static generation - required for Cloudflare Workers deployment
export const dynamic = 'force-static'

interface PageProps {
  params: Promise<{ slug: string }>
}

export async function generateStaticParams() {
  const posts = await getAllPosts()
  return posts.map((post) => ({ slug: post.slug }))
}

export async function generateMetadata({ params }: PageProps): Promise<Metadata> {
  const { slug } = await params
  const post = await getPost(slug)

  if (!post) {
    return {
      title: 'Post Not Found | SonicJS Blog',
    }
  }

  return {
    title: `${post.title} | SonicJS Blog`,
    description: post.description,
    keywords: post.keywords,
    authors: [{ name: post.author.name }],
    openGraph: {
      type: 'article',
      title: post.title,
      description: post.description,
      url: `https://sonicjs.com/blog/${post.slug}`,
      siteName: 'SonicJS',
      publishedTime: post.publishedAt,
      modifiedTime: post.updatedAt || post.publishedAt,
      authors: [post.author.name],
      images: [
        {
          url: post.featuredImage?.url || 'https://sonicjs.com/sonicjs-og.png',
          width: post.featuredImage?.width || 1792,
          height: post.featuredImage?.height || 1024,
          alt: post.title,
        },
      ],
      section: post.category,
      tags: post.tags,
    },
    twitter: {
      card: 'summary_large_image',
      title: post.title,
      description: post.description,
      images: [post.featuredImage?.url || 'https://sonicjs.com/sonicjs-og.png'],
    },
    alternates: {
      canonical: `https://sonicjs.com/blog/${post.slug}`,
    },
  }
}

export default async function BlogPostPage({ params }: PageProps) {
  const { slug } = await params
  const post = await getPost(slug)

  if (!post) {
    notFound()
  }

  const relatedPosts = await getRelatedPosts(post)

  const { content } = await compileMDX({
    source: post.content,
    components: {
      TLDRBox,
      Callout,
    },
    options: {
      mdxOptions: {
        remarkPlugins: [remarkGfm],
      },
    },
  })

  return (
    <>
      <BlogPostSchema post={post} />
      <BreadcrumbSchema post={post} />

      <article className="mx-auto max-w-4xl px-4 py-16 sm:px-6 lg:px-8">
        <BlogHeader post={post} />

        {/* Post Content */}
        <div className="prose prose-zinc mx-auto dark:prose-invert prose-headings:scroll-mt-20 prose-headings:font-semibold prose-a:text-emerald-600 prose-a:no-underline hover:prose-a:text-emerald-700 prose-code:rounded prose-code:bg-zinc-100 prose-code:px-1.5 prose-code:py-0.5 prose-code:font-normal prose-code:before:content-none prose-code:after:content-none prose-pre:bg-zinc-900 dark:prose-a:text-emerald-400 dark:hover:prose-a:text-emerald-300 dark:prose-code:bg-zinc-800 lg:prose-lg">
          {content}
        </div>

        {/* Tags */}
        {post.tags.length > 0 && (
          <div className="mt-10 flex flex-wrap gap-2">
            {post.tags.map((tag) => (
              <span
                key={tag}
                className="rounded-full bg-zinc-100 px-4 py-1.5 text-sm font-medium text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400"
              >
                #{tag}
              </span>
            ))}
          </div>
        )}

        <ShareButtons post={post} />
        <RelatedPosts posts={relatedPosts} />
      </article>
    </>
  )
}
