import fs from 'fs'
import path from 'path'
import matter from 'gray-matter'
import { BlogPost, BlogPostMeta, BlogCategory, DEFAULT_AUTHOR } from '@/types/blog'

const BLOG_CONTENT_PATH = path.join(process.cwd(), 'content/blog')

function calculateReadingTime(content: string): number {
  const wordsPerMinute = 200
  const words = content.trim().split(/\s+/).length
  return Math.ceil(words / wordsPerMinute)
}

function calculateWordCount(content: string): number {
  return content.trim().split(/\s+/).length
}

function getAllMdxFiles(dir: string): string[] {
  const files: string[] = []

  if (!fs.existsSync(dir)) {
    return files
  }

  const entries = fs.readdirSync(dir, { withFileTypes: true })

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      files.push(...getAllMdxFiles(fullPath))
    } else if (entry.name.endsWith('.mdx')) {
      files.push(fullPath)
    }
  }

  return files
}

export async function getAllPosts(): Promise<BlogPostMeta[]> {
  const files = getAllMdxFiles(BLOG_CONTENT_PATH)

  const posts = files
    .map((filePath) => {
      const fileContent = fs.readFileSync(filePath, 'utf-8')
      const { data, content } = matter(fileContent)

      // Skip drafts in production
      if (data.draft && process.env.NODE_ENV === 'production') {
        return null
      }

      // Skip future-dated posts in production (scheduled publishing)
      if (
        data.publishedAt &&
        new Date(data.publishedAt) > new Date() &&
        process.env.NODE_ENV === 'production'
      ) {
        return null
      }

      const slug = path.basename(filePath, '.mdx')

      return {
        slug,
        title: data.title || 'Untitled',
        description: data.description || '',
        keywords: data.keywords || [],
        category: data.category || 'guides',
        tags: data.tags || [],
        publishedAt: data.publishedAt || new Date().toISOString(),
        updatedAt: data.updatedAt,
        author: data.author || DEFAULT_AUTHOR,
        featuredImage: data.featuredImage,
        featured: data.featured || false,
        readingTime: calculateReadingTime(content),
        wordCount: calculateWordCount(content),
      } as BlogPostMeta
    })
    .filter((post): post is BlogPostMeta => post !== null)
    .sort((a, b) => new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime())

  return posts
}

export async function getPost(slug: string): Promise<BlogPost | null> {
  const files = getAllMdxFiles(BLOG_CONTENT_PATH)
  const filePath = files.find((f) => path.basename(f, '.mdx') === slug)

  if (!filePath) {
    return null
  }

  const fileContent = fs.readFileSync(filePath, 'utf-8')
  const { data, content } = matter(fileContent)

  // Skip drafts in production
  if (data.draft && process.env.NODE_ENV === 'production') {
    return null
  }

  // Skip future-dated posts in production (scheduled publishing)
  if (
    data.publishedAt &&
    new Date(data.publishedAt) > new Date() &&
    process.env.NODE_ENV === 'production'
  ) {
    return null
  }

  return {
    slug,
    title: data.title || 'Untitled',
    description: data.description || '',
    keywords: data.keywords || [],
    category: data.category || 'guides',
    tags: data.tags || [],
    publishedAt: data.publishedAt || new Date().toISOString(),
    updatedAt: data.updatedAt,
    author: data.author || DEFAULT_AUTHOR,
    featuredImage: data.featuredImage,
    featured: data.featured || false,
    content,
    readingTime: calculateReadingTime(content),
    wordCount: calculateWordCount(content),
  }
}

export async function getFeaturedPosts(): Promise<BlogPostMeta[]> {
  const posts = await getAllPosts()
  return posts.filter((post) => post.featured).slice(0, 1)
}

export async function getPostsByCategory(category: BlogCategory): Promise<BlogPostMeta[]> {
  const posts = await getAllPosts()
  return posts.filter((post) => post.category === category)
}

export async function getPostsByTag(tag: string): Promise<BlogPostMeta[]> {
  const posts = await getAllPosts()
  return posts.filter((post) => post.tags.includes(tag))
}

export async function getRelatedPosts(currentPost: BlogPost, limit = 3): Promise<BlogPostMeta[]> {
  const posts = await getAllPosts()

  // Filter out current post and score by relevance
  const scoredPosts = posts
    .filter((post) => post.slug !== currentPost.slug)
    .map((post) => {
      let score = 0

      // Same category = high score
      if (post.category === currentPost.category) {
        score += 10
      }

      // Matching tags
      const matchingTags = post.tags.filter((tag) => currentPost.tags.includes(tag))
      score += matchingTags.length * 5

      // Matching keywords
      const matchingKeywords = post.keywords.filter((kw) => currentPost.keywords.includes(kw))
      score += matchingKeywords.length * 3

      return { post, score }
    })
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score)

  return scoredPosts.slice(0, limit).map((item) => item.post)
}

export async function getAllTags(): Promise<string[]> {
  const posts = await getAllPosts()
  const tags = new Set<string>()

  posts.forEach((post) => {
    post.tags.forEach((tag) => tags.add(tag))
  })

  return Array.from(tags).sort()
}

export async function getAllCategories(): Promise<BlogCategory[]> {
  const posts = await getAllPosts()
  const categories = new Set<BlogCategory>()

  posts.forEach((post) => {
    categories.add(post.category)
  })

  return Array.from(categories)
}
