import { Hono } from 'hono'
import { html, raw } from 'hono/html'
import { z } from 'zod'
import type { D1Database, KVNamespace, R2Bucket } from '@cloudflare/workers-types'
import { requireAuth, requireRole } from '../middleware'
import { renderMediaLibraryPage, MediaLibraryPageData, FolderStats, TypeStats } from '../templates/pages/admin-media-library.template'
import { renderMediaFileDetails, MediaFileDetailsData } from '../templates/components/media-file-details.template'
import { MediaFile } from '../templates/components/media-grid.template'
import { MediaDocumentService, mediaDocToFile } from '../services/media-documents'
import { getRequestTenant } from '../services/document-request-context'
import { PluginService } from '../services/plugin-service'
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
    const limit = 24
    const offset = (page - 1) * limit

    const mediaSvc = new MediaDocumentService(c.env.DB, getRequestTenant(c))
    const { files, folders: folderAgg, types: typeAgg } = await mediaSvc.list({ folder, type, limit, offset })
    const mediaFiles: MediaFile[] = files.map(doc => mediaDocToFile(doc))
    
    const pageData: MediaLibraryPageData = {
      files: mediaFiles,
      folders: folderAgg.map(f => ({ folder: f.folder, count: f.count, totalSize: f.totalSize })) as FolderStats[],
      types: typeAgg.map(t => ({ type: t.type, count: t.count })) as TypeStats[],
      currentFolder: folder,
      currentType: type,
      currentView: view as 'grid' | 'list',
      currentPage: page,
      totalFiles: mediaFiles.length,
      hasNextPage: mediaFiles.length === limit,
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

    const pluginService = new PluginService(db)
    const mediaPlugin = await pluginService.getPlugin('core-media')
    if (!mediaPlugin || mediaPlugin.status !== 'active') {
      return c.html(html`
        <div class="text-center py-12">
          <svg class="mx-auto h-12 w-12 text-zinc-400 dark:text-zinc-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"></path>
          </svg>
          <p class="mt-2 text-sm font-medium text-zinc-700 dark:text-zinc-300">Media plugin is not enabled</p>
          <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">Enable the Media plugin in <a href="/admin/plugins" class="underline hover:text-zinc-700 dark:hover:text-zinc-200">Plugins</a> to use media selection.</p>
        </div>
      `)
    }

    const mediaSvc = new MediaDocumentService(db, getRequestTenant(c))
    const { files } = await mediaSvc.list({ search: search.trim() || undefined, limit: 24 })
    const mediaFiles = files.map(doc => mediaDocToFile(doc))

    // Build the cards once; the same markup serves both the full panel (the
    // initial modal load) and the grid-only fragment (HTMX search requests).
    const cardsHtml = mediaFiles.map(file => `
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
        `).join('')

    const gridInner = mediaFiles.length === 0
      ? `
        <div class="col-span-full text-center py-12 text-zinc-500 dark:text-zinc-400">
          <svg class="mx-auto h-12 w-12 text-zinc-400 dark:text-zinc-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
          </svg>
          <p class="mt-2">No media files found</p>
        </div>`
      : cardsHtml

    // On the HTMX search request the input targets #media-selector-grid, so
    // respond with only the inner cards. Returning the whole panel here (search
    // box + grid) would nest a fresh panel inside the grid on every keystroke,
    // and the search input had no `name`, so the typed term was never sent.
    if (c.req.header('HX-Target') === 'media-selector-grid') {
      return c.html(raw(gridInner))
    }

    // Initial modal load: full panel (search box + grid container).
    return c.html(html`
      <div class="mb-4">
        <input
          type="search"
          id="media-selector-search"
          name="search"
          placeholder="Search files..."
          class="w-full rounded-lg bg-white dark:bg-zinc-800 px-4 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow"
          hx-get="/admin/media/selector"
          hx-trigger="keyup changed delay:300ms, search"
          hx-target="#media-selector-grid"
          hx-include="[name='search']"
        >
      </div>

      <div id="media-selector-grid" class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-4 max-h-96 overflow-y-auto">
        ${raw(gridInner)}
      </div>
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
    
    const mediaSvc = new MediaDocumentService(db, getRequestTenant(c))
    const { files } = await mediaSvc.list({ folder, type, search: search.trim() || undefined, limit: 24 })
    const mediaFiles = files.map(doc => mediaDocToFile(doc))
    
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
    const mediaSvc = new MediaDocumentService(c.env.DB, getRequestTenant(c))
    const doc = await mediaSvc.getByRootId(id)

    if (!doc) {
      return c.html('<div class="text-red-500">File not found</div>')
    }

    const d = doc.data as Record<string, any>
    const base = mediaDocToFile(doc)
    const file: MediaFile & { width?: number; height?: number; folder: string; uploadedAt: string } = {
      ...base,
      uploadedAt: new Date((doc.createdAt ?? 0) * 1000).toLocaleString(),
      width: d.width ?? undefined,
      height: d.height ?? undefined,
      folder: d.folder ?? 'uploads',
    }

    return c.html(renderMediaFileDetails({ file }))
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

        // Generate unique filename and R2 key (fileId assigned from doc.rootId after document creation below)
        const fileExtension = file.name.split('.').pop() || ''
        const tempId = crypto.randomUUID()
        const filename = `${tempId}.${fileExtension}`
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

        // Create media_asset document (primary — rootId becomes the canonical file ID).
        const doc = await new MediaDocumentService(c.env.DB, getRequestTenant(c)).createFromUpload(
          { filename, originalName: file.name, mimeType: file.type, size: file.size, width, height, folder, r2Key },
          user!.userId,
        )
        const fileId = doc.rootId

        // R12: also write legacy media row (decommission after read-flip is stable).
        const publicUrl = `/files/${r2Key}`
        const thumbnailUrl = file.type.startsWith('image/') ? publicUrl : null
        try {
          await c.env.DB.prepare(`
            INSERT INTO media (
              id, filename, original_name, mime_type, size, width, height,
              folder, r2_key, public_url, thumbnail_url, uploaded_by, uploaded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            fileId, filename, file.name, file.type, file.size, width, height,
            folder, r2Key, publicUrl, thumbnailUrl, user!.userId, Math.floor(Date.now() / 1000)
          ).run()
        } catch { /* legacy table absent on fresh installs — non-fatal */ }

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
    const rootId = c.req.param('id')
    const formData = await c.req.formData()
    const tenantId = getRequestTenant(c)

    const mediaSvc = new MediaDocumentService(c.env.DB, tenantId)
    const doc = await mediaSvc.getByRootId(rootId)

    if (!doc) {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
          File not found
        </div>
      `)
    }

    if (doc.ownerId !== user!.userId && user!.role !== 'admin') {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
          Permission denied
        </div>
      `)
    }

    const alt = formData.get('alt') as string || null
    const caption = formData.get('caption') as string || null
    const tagsString = formData.get('tags') as string || ''
    const tags = tagsString ? tagsString.split(',').map(tag => tag.trim()).filter(t => t) : []

    await mediaSvc.updateMetadata(rootId, { alt, caption, tags }, user!.userId)

    // R12: keep legacy media row in sync
    try {
      await c.env.DB.prepare('UPDATE media SET alt = ?, caption = ?, tags = ?, updated_at = ? WHERE id = ?')
        .bind(alt, caption, JSON.stringify(tags), Math.floor(Date.now() / 1000), rootId)
        .run()
    } catch { /* legacy table may not have this row */ }

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

    // Find media files referenced in document content.
    const contentStmt = db.prepare("SELECT data FROM documents WHERE tenant_id = ? AND deleted_at IS NULL").bind(getRequestTenant(c))
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
    const rootId = c.req.param('id')
    const tenantId = getRequestTenant(c)

    const mediaSvc = new MediaDocumentService(c.env.DB, tenantId)
    const doc = await mediaSvc.getByRootId(rootId)

    if (!doc) {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
          File not found
        </div>
      `)
    }

    if (doc.ownerId !== user!.userId && user!.role !== 'admin') {
      return c.html(html`
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
          Permission denied
        </div>
      `)
    }

    // Reference-aware delete: block if any strong inbound refs exist.
    const impact = await mediaSvc.getDeleteImpact(rootId)
    if (!impact.canHardDelete) {
      return c.html(html`
        <div class="bg-amber-100 border border-amber-400 text-amber-800 px-4 py-3 rounded mb-4">
          This file is still used by ${impact.strongRefs.length} item(s) and cannot be deleted. Remove those references first, or archive it instead.
        </div>
      `)
    }

    const r2Key = (doc.data as Record<string, any>).r2Key as string | undefined

    // Delete from R2
    if (r2Key) {
      try {
        await c.env.MEDIA_BUCKET.delete(r2Key)
      } catch (e) {
        console.warn('Failed to delete from R2:', e)
      }
    }

    // Soft-delete document (all version rows for this root).
    await mediaSvc.softDeleteRoot(rootId)

    // R12: also soft-delete legacy media row (matched by id = rootId).
    try {
      await c.env.DB.prepare('UPDATE media SET deleted_at = ? WHERE id = ?')
        .bind(Math.floor(Date.now() / 1000), rootId)
        .run()
    } catch { /* legacy table may not have this row */ }

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
