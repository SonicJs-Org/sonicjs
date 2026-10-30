/**
 * Chunking Service
 * Splits content into optimal chunks for embedding and search
 */

export interface ContentChunk {
  id: string
  content_id: string
  collection_id: string
  title: string
  text: string
  chunk_index: number
  metadata: Record<string, any>
}

export class ChunkingService {
  // Default chunk size (in approximate tokens)
  private readonly CHUNK_SIZE = 500
  private readonly CHUNK_OVERLAP = 50

  /**
   * Chunk a single content item
   */
  chunkContent(
    contentId: string,
    collectionId: string,
    title: string,
    data: any,
    metadata: Record<string, any> = {}
  ): ContentChunk[] {
    // Extract all text from content
    const text = this.extractText(data)
    
    if (!text || text.trim().length === 0) {
      console.warn(`[ChunkingService] No text found for content ${contentId}`)
      return []
    }

    // Split into chunks
    const textChunks = this.splitIntoChunks(text)

    // Create chunk objects
    return textChunks.map((chunkText, index) => ({
      id: `${contentId}_chunk_${index}`,
      content_id: contentId,
      collection_id: collectionId,
      title: title,
      text: chunkText,
      chunk_index: index,
      metadata: {
        ...metadata,
        total_chunks: textChunks.length
      }
    }))
  }

  /**
   * Chunk multiple content items
   */
  chunkContentBatch(items: Array<{
    id: string
    collection_id: string
    title: string
    data: any
    metadata?: Record<string, any>
  }>): ContentChunk[] {
    const allChunks: ContentChunk[] = []

    for (const item of items) {
      const chunks = this.chunkContent(
        item.id,
        item.collection_id,
        item.title,
        item.data,
        item.metadata
      )
      allChunks.push(...chunks)
    }

    return allChunks
  }

  /**
   * Extract all text from content data
   */
  private extractText(data: any): string {
    const parts: string[] = []

    // Common text fields
    if (data.title) parts.push(String(data.title))
    if (data.name) parts.push(String(data.name))
    if (data.description) parts.push(String(data.description))
    if (data.content) parts.push(String(data.content))
    if (data.body) parts.push(String(data.body))
    if (data.text) parts.push(String(data.text))
    if (data.summary) parts.push(String(data.summary))

    // Recursively extract from nested objects
    const extractRecursive = (obj: any): void => {
      if (typeof obj === 'string') {
        // Skip very short strings and URLs
        if (obj.length > 10 && !obj.startsWith('http')) {
          parts.push(obj)
        }
      } else if (Array.isArray(obj)) {
        obj.forEach(extractRecursive)
      } else if (obj && typeof obj === 'object') {
        // Skip certain keys
        const skipKeys = ['id', 'slug', 'url', 'image', 'thumbnail', 'metadata']
        
        Object.entries(obj).forEach(([key, value]) => {
          if (!skipKeys.includes(key.toLowerCase())) {
            extractRecursive(value)
          }
        })
      }
    }

    extractRecursive(data)

    return parts.join('\n\n').trim()
  }

  /**
   * Split text into overlapping chunks
   */
  private splitIntoChunks(text: string): string[] {
    // Split by words
    const words = text.split(/\s+/)
    
    if (words.length <= this.CHUNK_SIZE) {
      return [text]
    }

    const chunks: string[] = []
    let startIndex = 0

    while (startIndex < words.length) {
      // Get chunk with overlap
      const endIndex = Math.min(startIndex + this.CHUNK_SIZE, words.length)
      const chunk = words.slice(startIndex, endIndex).join(' ')
      chunks.push(chunk)

      // Move forward by chunk size minus overlap
      startIndex += this.CHUNK_SIZE - this.CHUNK_OVERLAP

      // Ensure we don't create a tiny last chunk
      if (startIndex >= words.length - this.CHUNK_OVERLAP) {
        break
      }
    }

    return chunks
  }

  /**
   * Get optimal chunk size based on content type
   */
  getOptimalChunkSize(contentType: string): number {
    switch (contentType) {
      case 'blog_post':
      case 'articles':
        return 600 // Larger chunks for long-form content
      case 'products':
      case 'pages':
        return 400 // Medium chunks for structured content
      case 'messages':
      case 'comments':
        return 200 // Small chunks for short content
      default:
        return this.CHUNK_SIZE
    }
  }
}
