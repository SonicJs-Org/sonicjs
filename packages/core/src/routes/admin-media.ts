import { Hono } from 'hono'
import { html, raw } from 'hono/html'
import { z } from 'zod'
import type { D1Database, KVNamespace, R2Bucket } from '@cloudflare/workers-types'
import { requireAuth, requireRole } from '../middleware'
import { renderMediaLibraryPage, MediaLibraryPageData, FolderStats, TypeStats } from '../templates/pages/admin-media-library.template'
import { renderMediaFileDetails, MediaFileDetailsData } from '../templates/components/media-file-details.template'
import { MediaFile, renderMediaFileCard } from '../templates/components/media-grid.template'
import type { Bindings, Variables } from '../app'

// File validation schema
const fileValidationSchema = z.object({
  name: z.string().min(1).max(255),
  type: z.string().refine(
    (type) => {
      const allowedTypes = [
        // Images
        'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml',
        // Documents
        'application/pdf', 'text/plain', 'application/msword', 
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        // Videos
        'video/mp4', 'video/webm', 'video/ogg', 'video/avi', 'video/mov',
        // Audio
        'audio/mp3', 'audio/wav', 'audio/ogg', 'audio/m4a'
      ]
      return allowedTypes.includes(type)
    },
    { message: 'Unsupported file type' }
  ),
  size: z.number().min(1).max(50 * 1024 * 1024) // 50MB max
})

const adminMediaRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Apply authentication middleware
adminMediaRoutes.use('*', requireAuth())

// Media library main page
adminMediaRoutes.get('/', async (c) => {
  try {
    const user = c.get('user')
    const { searchParams } = new URL(c.req.url)
    const folder = searchParams.get('folder') || 'all'
    const type = searchParams.get('type') || 'all'
    const view = searchParams.get('view') || 'grid'
    const page = parseInt(searchParams.get('page') || '1')
    const _cacheBust = searchParams.get('t') // Cache-busting parameter
    const limit = 24
    const offset = (page - 1) * limit

    const db = c.env.DB

    // TODO: Cache implementation removed during migration - will be added back when cache plugin is migrated

    // Build query for media files
    let query = 'SELECT * FROM media'
    const params: any[] = []
    const conditions: string[] = ['deleted_at IS NULL']
    
    if (folder !== 'all') {
      conditions.push('folder = ?')
      params.push(folder)
    }
    
    if (type !== 'all') {
      switch (type) {
        case 'images':
          conditions.push('mime_type LIKE ?')
          params.push('image/%')
          break
        case 'documents':
          conditions.push('mime_type IN (?, ?, ?)')
          params.push('application/pdf', 'text/plain', 'application/msword')
          break
        case 'videos':
          conditions.push('mime_type LIKE ?')
          params.push('video/%')
          break
      }
    }
    
    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(' AND ')}`
    }
    
    query += ` ORDER BY uploaded_at DESC LIMIT ${limit} OFFSET ${offset}`
    
    const stmt = db.prepare(query)
    const { results } = await stmt.bind(...params).all()
    
    // Get folder statistics
    const foldersStmt = db.prepare(`
      SELECT folder, COUNT(*) as count, SUM(size) as totalSize
      FROM media
      WHERE deleted_at IS NULL
      GROUP BY folder
      ORDER BY folder
    `)
    const { results: folders } = await foldersStmt.all()
    
    // Get type statistics
    const typesStmt = db.prepare(`
      SELECT
        CASE
          WHEN mime_type LIKE 'image/%' THEN 'images'
          WHEN mime_type LIKE 'video/%' THEN 'videos'
          WHEN mime_type IN ('application/pdf', 'text/plain') THEN 'documents'
          ELSE 'other'
        END as type,
        COUNT(*) as count
      FROM media
      WHERE deleted_at IS NULL
      GROUP BY type
    `)
    const { results: types } = await typesStmt.all()
    
    // Process media files with local serving URLs
    const mediaFiles: MediaFile[] = results.map((row: any) => ({
      id: row.id,
      filename: row.filename,
      original_name: row.original_name,
      mime_type: row.mime_type,
      size: row.size,
      public_url: `/files/${row.r2_key}`,
      thumbnail_url: row.mime_type.startsWith('image/') ? `/files/${row.r2_key}` : undefined,
      alt: row.alt,
      caption: row.caption,
      tags: row.tags ? JSON.parse(row.tags) : [],
      uploaded_at: row.uploaded_at,
      fileSize: formatFileSize(row.size),
      uploadedAt: new Date(row.uploaded_at).toLocaleDateString(),
      isImage: row.mime_type.startsWith('image/'),
      isVideo: row.mime_type.startsWith('video/'),
      isDocument: !row.mime_type.startsWith('image/') && !row.mime_type.startsWith('video/')
    }))
    
    const pageData: MediaLibraryPageData = {
      files: mediaFiles,
      folders: folders.map((f: any) => ({
        folder: f.folder,
        count: f.count,
        totalSize: f.totalSize
      })) as FolderStats[],
      types: types.map((t: any) => ({
        type: t.type,
        count: t.count
      })) as TypeStats[],
      currentFolder: folder,
      currentType: type,
      currentView: view as 'grid' | 'list',
      currentPage: page,
      totalFiles: results.length,
      hasNextPage: results.length === limit,
      user: {
        name: user!.email,
        email: user!.email,
        role: user!.role
      },
      version: c.get('appVersion')
    }

    // TODO: Cache implementation removed during migration

    return c.html(renderMediaLibraryPage(pageData))
  } catch (error) {
    console.error('Error loading media library:', error)
    return c.html(html`<p>Error loading media library</p>`)
  }
})

// Media selector endpoint (HTMX endpoint for content form media selection)
adminMediaRoutes.get('/selector', async (c) => {
  try {
    const { searchParams } = new URL(c.req.url)
    const search = searchParams.get('search') || ''
    const db = c.env.DB

    // Build search query
    let query = 'SELECT * FROM media WHERE deleted_at IS NULL'
    const params: any[] = []

    if (search.trim()) {
      query += ' AND (filename LIKE ? OR original_name LIKE ? OR alt LIKE ?)'
      const searchTerm = `%${search}%`
      params.push(searchTerm, searchTerm, searchTerm)
    }

    query += ' ORDER BY uploaded_at DESC LIMIT 24'

    const stmt = db.prepare(query)
    const { results } = await stmt.bind(...params).all()

    const mediaFiles = results.map((row: any) => ({
      id: row.id,
      filename: row.filename,
      original_name: row.original_name,
      mime_type: row.mime_type,
      size: row.size,
      public_url: `/files/${row.r2_key}`,
      thumbnail_url: row.mime_type.startsWith('image/') ? `/files/${row.r2_key}` : undefined,
      alt: row.alt,
      tags: row.tags ? JSON.parse(row.tags) : [],
      uploaded_at: row.uploaded_at,
      fileSize: formatFileSize(row.size),
      uploadedAt: new Date(row.uploaded_at).toLocaleDateString(),
      isImage: row.mime_type.startsWith('image/'),
      isVideo: row.mime_type.startsWith('video/'),
      isDocument: !row.mime_type.startsWith('image/') && !row.mime_type.startsWith('video/')
    }))

    // Render media selector grid
    return c.html(html`
      <div class="mb-4">
        <input
          type="search"
          id="media-selector-search"
          placeholder="Search files..."
          class="w-full rounded-lg bg-white dark:bg-zinc-800 px-4 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow"
          hx-get="/admin/media/selector"
          hx-trigger="keyup changed delay:300ms"
          hx-target="#media-selector-grid"
          hx-include="[name='search']"
        >
      </div>

      <div id="media-selector-grid" class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-4 max-h-96 overflow-y-auto">
        ${raw(mediaFiles.map(file => `
          <div
            class="relative group cursor-pointer rounded-lg overflow-hidden bg-zinc-50 dark:bg-zinc-800 shadow-sm hover:shadow-md transition-shadow"
            data-media-id="${file.id}"
          >
            <div class="aspect-square relative">
              ${file.isImage ? `
                <img
                  src="${file.public_url}"
                  alt="${file.alt || file.filename}"
                  class="w-full h-full object-cover"
                  loading="lazy"
                >
              ` : file.isVideo ? `
                <video
                  src="${file.public_url}"
                  class="w-full h-full object-cover"
                  muted
                ></video>
              ` : `
                <div class="w-full h-full flex items-center justify-center bg-zinc-100 dark:bg-zinc-700">
                  <div class="text-center">
                    <svg class="w-12 h-12 mx-auto text-zinc-400 dark:text-zinc-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                    </svg>
                    <span class="text-xs text-zinc-500 dark:text-zinc-400 mt-1">${file.filename.split('.').pop()?.toUpperCase()}</span>
                  </div>
                </div>
              `}

              <div class="absolute inset-0 bg-black/50 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                <button
                  type="button"
                  onclick="selectMediaFile('${file.id}', '${file.public_url.replace(/'/g, "\\'")}', '${file.filename.replace(/'/g, "\\'")}')"
                  class="px-4 py-2 bg-white dark:bg-zinc-900 text-zinc-950 dark:text-white rounded-lg font-medium hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors"
                >
                  Select
                </button>
              </div>
            </div>

            <div class="p-2">
              <p class="text-xs text-zinc-700 dark:text-zinc-300 truncate" title="${file.original_name}">
                ${file.original_name}
              </p>
              <p class="text-xs text-zinc-500 dark:text-zinc-400">
                ${file.fileSize}
              </p>
            </div>
          </div>
        `).join(''))}
      </div>

      ${mediaFiles.length === 0 ? html`
        <div class="text-center py-12 text-zinc-500 dark:text-zinc-400">
          <svg class="mx-auto h-12 w-12 text-zinc-400 dark:text-zinc-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
          </svg>
          <p class="mt-2">No media files found</p>
        </div>
      ` : ''}
    `)
  } catch (error) {
    console.error('Error loading media selector:', error)
    return c.html(html`<div class="text-red-500 dark:text-red-400">Error loading media files</div>`)
  }
})

// Search media files (HTMX endpoint)
adminMediaRoutes.get('/search', async (c) => {
  try {
    const { searchParams } = new URL(c.req.url)
    const search = searchParams.get('search') || ''
    const folder = searchParams.get('folder') || 'all'
    const type = searchParams.get('type') || 'all'
    const db = c.env.DB
    
    // Build search query
    let query = 'SELECT * FROM media'
    const params: any[] = []
    const conditions: string[] = []
    
    if (search.trim()) {
      conditions.push('(filename LIKE ? OR original_name LIKE ? OR alt LIKE ?)')
      const searchTerm = `%${search}%`
      params.push(searchTerm, searchTerm, searchTerm)
    }
    
    if (folder !== 'all') {
      conditions.push('folder = ?')
      params.push(folder)
    }
    
    if (type !== 'all') {
      switch (type) {
        case 'images':
          conditions.push('mime_type LIKE ?')
          params.push('image/%')
          break
        case 'documents':
          conditions.push('mime_type IN (?, ?, ?)')
          params.push('application/pdf', 'text/plain', 'application/msword')
          break
        case 'videos':
          conditions.push('mime_type LIKE ?')
          params.push('video/%')
          break
      }
    }
    
    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(' AND ')}`
    }
    
    query += ` ORDER BY uploaded_at DESC LIMIT 24`
    
    const stmt = db.prepare(query)
    const { results } = await stmt.bind(...params).all()
    
    const mediaFiles = results.map((row: any) => ({
      ...row,
      public_url: `/files/${row.r2_key}`,
      thumbnail_url: row.mime_type.startsWith('image/') ? `/files/${row.r2_key}` : undefined,
      tags: row.tags ? JSON.parse(row.tags) : [],
      uploadedAt: new Date(row.uploaded_at).toLocaleDateString(),
      fileSize: formatFileSize(row.size),
      isImage: row.mime_type.startsWith('image/'),
      isVideo: row.mime_type.startsWith('video/'),
      isDocument: !row.mime_type.startsWith('image/') && !row.mime_type.startsWith('video/')
    }))
    
    const gridHTML = mediaFiles.map(file => generateMediaItemHTML(file)).join('')
    
    return c.html(raw(gridHTML))
  } catch (error) {
    console.error('Error searching media:', error)
    return c.html('<div class="text-red-500">Error searching files</div>')
  }
})

// Get file details modal (HTMX endpoint)
adminMediaRoutes.get('/:id/details', async (c) => {
  try {
    const id = c.req.param('id')
    const db = c.env.DB
    
    const stmt = db.prepare('SELECT * FROM media WHERE id = ?')
    const result = await stmt.bind(id).first() as any
    
    if (!result) {
      return c.html('<div class="text-red-500">File not found</div>')
    }
    
    const file: MediaFile & { width?: number; height?: number; folder: string; uploadedAt: string } = {
      id: result.id,
      filename: result.filename,
      original_name: result.original_name,
      mime_type: result.mime_type,
      size: result.size,
      public_url: `/files/${result.r2_key}`,
      thumbnail_url: result.mime_type.startsWith('image/') ? `/files/${result.r2_key}` : undefined,
      alt: result.alt,
      caption: result.caption,
      tags: result.tags ? JSON.parse(result.tags) : [],
      uploaded_at: result.uploaded_at,
      fileSize: formatFileSize(result.size),
      uploadedAt: new Date(result.uploaded_at).toLocaleString(),
      isImage: result.mime_type.startsWith('image/'),
      isVideo: result.mime_type.startsWith('video/'),
      isDocument: !result.mime_type.startsWith('image/') && !result.mime_type.startsWith('video/'),
      width: result.width,
      height: result.height,
      folder: result.folder
    }
    
    const detailsData: MediaFileDetailsData = { file }
    
    return c.html(renderMediaFileDetails(detailsData))
  } catch (error) {
    console.error('Error fetching file details:', error)
    return c.html('<div class="text-red-500">Error loading file details</div>')
  }
})

// Upload files endpoint (HTMX compatible)
adminMediaRoutes.post('/upload', async (c) => {
  try {
    const user = c.get('user')
    const formData = await c.req.formData()
    const fileEntries = formData.getAll('files') as unknown[]
    const files: File[] = []

    for (const entry of fileEntries) {
      if (entry instanceof File) {
        files.push(entry)
      }
    }
    
    if (!files || files.length === 0) {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          No files provided
        </div>
      `)
    }

    const uploadResults = []
    const errors = []

    // Check if MEDIA_BUCKET is available
    console.log('[MEDIA UPLOAD] c.env keys:', Object.keys(c.env))
    console.log('[MEDIA UPLOAD] MEDIA_BUCKET defined?', !!c.env.MEDIA_BUCKET)
    console.log('[MEDIA UPLOAD] MEDIA_BUCKET type:', typeof c.env.MEDIA_BUCKET)

    if (!c.env.MEDIA_BUCKET) {
      console.error('[MEDIA UPLOAD] MEDIA_BUCKET is not available! Available env keys:', Object.keys(c.env))
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          Media storage (R2) is not configured. Please check your wrangler.toml configuration.
          <br><small>Debug: Available bindings: ${Object.keys(c.env).join(', ')}</small>
        </div>
      `)
    }

    for (const file of files) {
      try {
        // Validate file
        const validation = fileValidationSchema.safeParse({
          name: file.name,
          type: file.type,
          size: file.size
        })

        if (!validation.success) {
          errors.push({
            filename: file.name,
            error: validation.error.issues[0]?.message || 'Validation failed'
          })
          continue
        }

        // Generate unique filename and R2 key
        const fileId = crypto.randomUUID()
        const fileExtension = file.name.split('.').pop() || ''
        const filename = `${fileId}.${fileExtension}`
        const folder = formData.get('folder') as string || 'uploads'
        const r2Key = `${folder}/${filename}`

        // Upload to R2
        const arrayBuffer = await file.arrayBuffer()
        const uploadResult = await c.env.MEDIA_BUCKET.put(r2Key, arrayBuffer, {
          httpMetadata: {
            contentType: file.type,
            contentDisposition: `inline; filename="${file.name}"`
          },
          customMetadata: {
            originalName: file.name,
            uploadedBy: user!.userId,
            uploadedAt: new Date().toISOString()
          }
        })

        if (!uploadResult) {
          errors.push({
            filename: file.name,
            error: 'Failed to upload to storage'
          })
          continue
        }

        // Extract image dimensions if it's an image
        let width: number | null = null
        let height: number | null = null

        if (file.type.startsWith('image/') && !file.type.includes('svg')) {
          try {
            const dimensions = await getImageDimensions(arrayBuffer)
            width = dimensions.width
            height = dimensions.height
          } catch (error) {
            console.warn('Failed to extract image dimensions:', error)
          }
        }

        // Generate URLs - use public serving route
        const publicUrl = `/files/${r2Key}`
        const thumbnailUrl = file.type.startsWith('image/') ? publicUrl : null

        // Save to database
        const stmt = c.env.DB.prepare(`
          INSERT INTO media (
            id, filename, original_name, mime_type, size, width, height, 
            folder, r2_key, public_url, thumbnail_url, uploaded_by, uploaded_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        
        await stmt.bind(
          fileId,
          filename,
          file.name,
          file.type,
          file.size,
          width,
          height,
          folder,
          r2Key,
          publicUrl,
          thumbnailUrl,
          user!.userId,
          Math.floor(Date.now() / 1000)
        ).run()

        uploadResults.push({
          id: fileId,
          filename: filename,
          originalName: file.name,
          mimeType: file.type,
          size: file.size,
          publicUrl: publicUrl
        })
      } catch (error) {
        errors.push({
          filename: file.name,
          error: 'Upload failed: ' + (error instanceof Error ? error.message : 'Unknown error')
        })
      }
    }

    // TODO: Cache invalidation removed during migration

    // Fetch updated media list to include in response
    let mediaGridHTML = ''
    if (uploadResults.length > 0) {
      try {
        const folderEntry = formData.get('folder')
        const folder = typeof folderEntry === 'string' ? folderEntry : 'uploads'
        const query = 'SELECT * FROM media WHERE deleted_at IS NULL ORDER BY uploaded_at DESC LIMIT 24'
        const stmt = c.env.DB.prepare(query)
        const { results } = await stmt.all()

        const mediaFiles = results.map((row: any) => ({
          id: row.id,
          filename: row.filename,
          original_name: row.original_name,
          mime_type: row.mime_type,
          size: row.size,
          public_url: `/files/${row.r2_key}`,
          thumbnail_url: row.mime_type.startsWith('image/') ? `/files/${row.r2_key}` : undefined,
          tags: row.tags ? JSON.parse(row.tags) : [],
          uploaded_at: row.uploaded_at,
          fileSize: formatFileSize(row.size),
          uploadedAt: new Date(row.uploaded_at).toLocaleDateString(),
          isImage: row.mime_type.startsWith('image/'),
          isVideo: row.mime_type.startsWith('video/'),
          isDocument: !row.mime_type.startsWith('image/') && !row.mime_type.startsWith('video/')
        }))

        mediaGridHTML = mediaFiles.map(file => renderMediaFileCard(file, 'grid', true)).join('')
      } catch (error) {
        console.error('Error fetching updated media list:', error)
      }
    }

    // Return HTMX response with results
    return c.html(html`
      ${uploadResults.length > 0 ? html`
        <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-4">
          Successfully uploaded ${uploadResults.length} file${uploadResults.length > 1 ? 's' : ''}
        </div>
      ` : ''}

      ${errors.length > 0 ? html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          <p class="font-medium">Upload errors:</p>
          <ul class="list-disc list-inside mt-2">
            ${errors.map(error => html`
              <li>${error.filename}: ${error.error}</li>
            `)}
          </ul>
        </div>
      ` : ''}

      ${uploadResults.length > 0 ? html`
        <script>
          // Close modal and refresh page after successful upload with cache busting
          setTimeout(() => {
            document.getElementById('upload-modal').classList.add('hidden');
            window.location.href = '/admin/media?t=' + Date.now();
          }, 1500);
        </script>
      ` : ''}
    `)
  } catch (error) {
    console.error('Upload error:', error)
    return c.html(html`
      <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
        Upload failed: ${error instanceof Error ? error.message : 'Unknown error'}
      </div>
    `)
  }
})

// Serve files from R2 storage
adminMediaRoutes.get('/file/*', async (c) => {
  try {
    const r2Key = c.req.path.replace('/admin/media/file/', '')
    
    if (!r2Key) {
      return c.notFound()
    }

    // Get file from R2
    const object = await c.env.MEDIA_BUCKET.get(r2Key)
    
    if (!object) {
      return c.notFound()
    }

    // Set appropriate headers
    const headers = new Headers()
    object.httpMetadata?.contentType && headers.set('Content-Type', object.httpMetadata.contentType)
    object.httpMetadata?.contentDisposition && headers.set('Content-Disposition', object.httpMetadata.contentDisposition)
    headers.set('Cache-Control', 'public, max-age=31536000') // 1 year cache
    
    return new Response(object.body as any, {
      headers
    })
  } catch (error) {
    console.error('Error serving file:', error)
    return c.notFound()
  }
})

// Update media file metadata (HTMX compatible)
adminMediaRoutes.put('/:id', async (c) => {
  try {
    const user = c.get('user')
    const fileId = c.req.param('id')
    const formData = await c.req.formData()
    
    // Get file record
    const stmt = c.env.DB.prepare('SELECT * FROM media WHERE id = ? AND deleted_at IS NULL')
    const fileRecord = await stmt.bind(fileId).first() as any
    
    if (!fileRecord) {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
          File not found
        </div>
      `)
    }

    // Check permissions (only allow updates by uploader or admin)
    if (fileRecord.uploaded_by !== user!.userId && user!.role !== 'admin') {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
          Permission denied
        </div>
      `)
    }

    // Extract form data
    const alt = formData.get('alt') as string || null
    const caption = formData.get('caption') as string || null
    const tagsString = formData.get('tags') as string || ''
    const tags = tagsString ? tagsString.split(',').map(tag => tag.trim()).filter(tag => tag) : []

    // Update database
    const updateStmt = c.env.DB.prepare(`
      UPDATE media 
      SET alt = ?, caption = ?, tags = ?, updated_at = ?
      WHERE id = ?
    `)
    await updateStmt.bind(
      alt,
      caption,
      JSON.stringify(tags),
      Math.floor(Date.now() / 1000),
      fileId
    ).run()

    // TODO: Cache invalidation removed during migration

    return c.html(html`
      <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-4">
        File updated successfully
      </div>
      <script>
        // Refresh the file details
        setTimeout(() => {
          htmx.trigger('#file-modal-content', 'htmx:load');
        }, 1000);
      </script>
    `)
  } catch (error) {
    console.error('Update error:', error)
    return c.html(html`
      <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
        Update failed: ${error instanceof Error ? error.message : 'Unknown error'}
      </div>
    `)
  }
})

// Cleanup unused media files (HTMX compatible)
adminMediaRoutes.delete('/cleanup', requireRole('admin'), async (c) => {
  try {
    const db = c.env.DB

    // Find all media files
    const allMediaStmt = db.prepare('SELECT id, r2_key, filename FROM media WHERE deleted_at IS NULL')
    const { results: allMedia } = await allMediaStmt.all<{ id: string; r2_key: string; filename: string }>()

    // Find media files referenced in content
    // Content can reference media in various JSON fields like data, hero_image, etc.
    const contentStmt = db.prepare('SELECT data FROM content')
    const { results: contentRecords } = await contentStmt.all<{ data: unknown }>()

    // Extract all media URLs from content
    const referencedUrls = new Set<string>()
    for (const record of contentRecords || []) {
      if (record.data) {
        const dataStr = typeof record.data === 'string' ? record.data : JSON.stringify(record.data)
        // Find all /files/ URLs in the content
        const urlMatches = dataStr.matchAll(/\/files\/([^\s"',]+)/g)
        for (const match of urlMatches) {
          referencedUrls.add(match[1]!)
        }
      }
    }

    // Find unreferenced media files
    const mediaRows = allMedia || []
    const unusedFiles = mediaRows.filter((file) => !referencedUrls.has(file.r2_key))

    if (unusedFiles.length === 0) {
      return c.html(html`
        <div class="bg-blue-100 border border-blue-400 text-blue-700 px-4 py-3 rounded">
          No unused media files found. All files are referenced in content.
        </div>
        <script>
          setTimeout(() => {
            window.location.href = '/admin/media?t=' + Date.now();
          }, 2000);
        </script>
      `)
    }

    // Delete unused files from R2 and database
    let deletedCount = 0
    const errors = []

    for (const file of unusedFiles) {
      try {
        // Delete from R2
        await c.env.MEDIA_BUCKET.delete(file.r2_key)

        // Soft delete in database
        const deleteStmt = db.prepare('UPDATE media SET deleted_at = ? WHERE id = ?')
        await deleteStmt.bind(Math.floor(Date.now() / 1000), file.id).run()

        deletedCount++
      } catch (error) {
        console.error(`Failed to delete ${file.filename}:`, error)
        errors.push({
          filename: file.filename,
          error: error instanceof Error ? error.message : 'Unknown error'
        })
      }
    }

    // Return success response
    return c.html(html`
      <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-4">
        Successfully cleaned up ${deletedCount} unused media file${deletedCount !== 1 ? 's' : ''}.
        ${errors.length > 0 ? html`
          <br><span class="text-sm">Failed to delete ${errors.length} file${errors.length !== 1 ? 's' : ''}.</span>
        ` : ''}
      </div>

      ${errors.length > 0 ? html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
          <p class="font-medium">Cleanup errors:</p>
          <ul class="list-disc list-inside mt-2 text-sm">
            ${errors.map(error => html`
              <li>${error.filename}: ${error.error}</li>
            `)}
          </ul>
        </div>
      ` : ''}

      <script>
        // Refresh media library after cleanup
        setTimeout(() => {
          window.location.href = '/admin/media?t=' + Date.now();
        }, 2500);
      </script>
    `)
  } catch (error) {
    console.error('Cleanup error:', error)
    return c.html(html`
      <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
        Cleanup failed: ${error instanceof Error ? error.message : 'Unknown error'}
      </div>
    `)
  }
})

// Delete media file (HTMX compatible)
adminMediaRoutes.delete('/:id', async (c) => {
  try {
    const user = c.get('user')
    const fileId = c.req.param('id')

    // Get file record
    const stmt = c.env.DB.prepare('SELECT * FROM media WHERE id = ? AND deleted_at IS NULL')
    const fileRecord = await stmt.bind(fileId).first() as any

    if (!fileRecord) {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
          File not found
        </div>
      `)
    }

    // Check permissions (only allow deletion by uploader or admin)
    if (fileRecord.uploaded_by !== user!.userId && user!.role !== 'admin') {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
          Permission denied
        </div>
      `)
    }

    // Delete from R2
    try {
      await c.env.MEDIA_BUCKET.delete(fileRecord.r2_key)
    } catch (error) {
      console.warn('Failed to delete from R2:', error)
      // Continue with database deletion even if R2 deletion fails
    }

    // Soft delete in database
    const deleteStmt = c.env.DB.prepare('UPDATE media SET deleted_at = ? WHERE id = ?')
    await deleteStmt.bind(Math.floor(Date.now() / 1000), fileId).run()

    // TODO: Cache invalidation removed during migration

    // Return HTMX response that redirects to media library
    return c.html(html`
      <script>
        // Close modal if open
        const modal = document.getElementById('file-modal');
        if (modal) {
          modal.classList.add('hidden');
        }
        // Redirect to media library
        window.location.href = '/admin/media';
      </script>
    `)
  } catch (error) {
    console.error('Delete error:', error)
    return c.html(html`
      <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
        Delete failed: ${error instanceof Error ? error.message : 'Unknown error'}
      </div>
    `)
  }
})

// Helper function to extract image dimensions
async function getImageDimensions(arrayBuffer: ArrayBuffer): Promise<{ width: number; height: number }> {
  const uint8Array = new Uint8Array(arrayBuffer)
  
  // Check for JPEG
  if (uint8Array[0] === 0xFF && uint8Array[1] === 0xD8) {
    return getJPEGDimensions(uint8Array)
  }
  
  // Check for PNG
  if (uint8Array[0] === 0x89 && uint8Array[1] === 0x50 && uint8Array[2] === 0x4E && uint8Array[3] === 0x47) {
    return getPNGDimensions(uint8Array)
  }
  
  // Default fallback
  return { width: 0, height: 0 }
}

function getJPEGDimensions(uint8Array: Uint8Array): { width: number; height: number } {
  let i = 2
  while (i < uint8Array.length - 8) {
    if (uint8Array[i] === 0xFF && uint8Array[i + 1] === 0xC0) {
      return {
        height: (uint8Array[i + 5]! << 8) | uint8Array[i + 6]!,
        width: (uint8Array[i + 7]! << 8) | uint8Array[i + 8]!
      }
    }
    const segmentLength = (uint8Array[i + 2]! << 8) | uint8Array[i + 3]!
    i += 2 + segmentLength
  }
  return { width: 0, height: 0 }
}

function getPNGDimensions(uint8Array: Uint8Array): { width: number; height: number } {
  if (uint8Array.length < 24) {
    return { width: 0, height: 0 }
  }
  return {
    width: (uint8Array[16]! << 24) | (uint8Array[17]! << 16) | (uint8Array[18]! << 8) | uint8Array[19]!,
    height: (uint8Array[20]! << 24) | (uint8Array[21]! << 16) | (uint8Array[22]! << 8) | uint8Array[23]!
  }
}

// Helper function to generate media item HTML
function generateMediaItemHTML(file: any): string {
  const isImage = file.isImage
  const isVideo = file.isVideo
  
  return `
    <div 
      class="media-item bg-white rounded-lg shadow-sm overflow-hidden cursor-pointer" 
      data-file-id="${file.id}"
      onclick="toggleFileSelection('${file.id}')"
    >
      <div class="aspect-square relative">
        ${isImage ? `
          <img 
            src="${file.public_url}" 
            alt="${file.alt || file.filename}"
            class="w-full h-full object-cover"
            loading="lazy"
          >
        ` : isVideo ? `
          <video 
            src="${file.public_url}" 
            class="w-full h-full object-cover"
            muted
          ></video>
        ` : `
          <div class="w-full h-full flex items-center justify-center bg-gray-100">
            <div class="text-center">
              <svg class="file-icon mx-auto text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
              </svg>
              <span class="text-xs text-gray-500 mt-1">${file.filename.split('.').pop()?.toUpperCase()}</span>
            </div>
          </div>
        `}
        
        <div class="preview-overlay flex items-center justify-center">
          <div class="flex space-x-2">
            <button 
              onclick="event.stopPropagation(); showFileDetails('${file.id}')"
              class="p-2 bg-white bg-opacity-20 rounded-full hover:bg-opacity-30"
            >
              <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
              </svg>
            </button>
            <button 
              onclick="event.stopPropagation(); copyToClipboard('${file.public_url}')"
              class="p-2 bg-white bg-opacity-20 rounded-full hover:bg-opacity-30"
            >
              <svg class="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
              </svg>
            </button>
          </div>
        </div>
      </div>
      
      <div class="p-3">
        <h4 class="text-sm font-medium text-gray-900 truncate" title="${file.original_name}">
          ${file.original_name}
        </h4>
        <div class="flex justify-between items-center mt-1">
          <span class="text-xs text-gray-500">${file.fileSize}</span>
          <span class="text-xs text-gray-500">${file.uploadedAt}</span>
        </div>
        ${file.tags.length > 0 ? `
          <div class="flex flex-wrap gap-1 mt-2">
            ${file.tags.slice(0, 2).map((tag: string) => `
              <span class="inline-block px-2 py-1 text-xs bg-gray-100 text-gray-600 rounded">
                ${tag}
              </span>
            `).join('')}
            ${file.tags.length > 2 ? `<span class="text-xs text-gray-400">+${file.tags.length - 2}</span>` : ''}
          </div>
        ` : ''}
      </div>
    </div>
  `
}

// Helper function to format file size
function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 Bytes'
  const k = 1024
  const sizes = ['Bytes', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

export { adminMediaRoutes }
