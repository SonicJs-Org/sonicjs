import { MediaFile } from './media-grid.template'

export interface MediaFileDetailsData {
  file: MediaFile & {
    width?: number
    height?: number
    folder: string
    uploadedAt: string
  }
}

export function renderMediaFileDetails(data: MediaFileDetailsData): string {
  const { file } = data
  
  return `
    <div class="flex justify-between items-center mb-4">
      <h3 class="text-lg font-semibold text-zinc-950 dark:text-white">File Details</h3>
      <button onclick="document.getElementById('file-modal').classList.add('hidden')" class="text-zinc-500 dark:text-zinc-400 hover:text-zinc-950 dark:hover:text-white transition-colors">
        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
        </svg>
      </button>
    </div>
    
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <!-- Preview -->
      <div class="space-y-4">
        <div class="rounded-xl bg-zinc-50 dark:bg-zinc-800 p-4">
          ${file.isImage ? `
            <img src="${file.public_url}" alt="${file.alt || file.filename}" class="w-full h-auto rounded-lg">
          ` : file.isVideo ? `
            <video src="${file.public_url}" controls class="w-full h-auto rounded-lg"></video>
          ` : `
            <div class="flex items-center justify-center h-32">
              <svg class="w-12 h-12 text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
              </svg>
            </div>
          `}
        </div>

        <div class="text-center space-x-2">
          <button
            onclick="copyToClipboard('${file.public_url}')"
            class="inline-flex items-center rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-700 transition-colors"
          >
            Copy Relative URL
          </button>
          <a
            href="${file.public_url}"
            target="_blank"
            class="inline-flex items-center rounded-lg bg-white dark:bg-zinc-800 px-4 py-2 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors"
          >
            Open Original
          </a>
        </div>
      </div>
      
      <!-- Details -->
      <div class="space-y-4">
        <div>
          <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-1">Filename</label>
          <p class="text-sm text-zinc-500 dark:text-zinc-400">${file.original_name}</p>
        </div>

        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-1">Size</label>
            <p class="text-sm text-zinc-500 dark:text-zinc-400">${file.fileSize}</p>
          </div>
          <div>
            <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-1">Type</label>
            <p class="text-sm text-zinc-500 dark:text-zinc-400">${file.mime_type}</p>
          </div>
        </div>

        ${file.width && file.height ? `
          <div class="grid grid-cols-2 gap-4">
            <div>
              <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-1">Width</label>
              <p class="text-sm text-zinc-500 dark:text-zinc-400">${file.width}px</p>
            </div>
            <div>
              <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-1">Height</label>
              <p class="text-sm text-zinc-500 dark:text-zinc-400">${file.height}px</p>
            </div>
          </div>
        ` : ''}

        <div>
          <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-1">Folder</label>
          <p class="text-sm text-zinc-500 dark:text-zinc-400">${file.folder}</p>
        </div>

        <div>
          <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-1">URL</label>
          <a
            href="${file.public_url}"
            target="_blank"
            rel="noopener noreferrer"
            class="text-sm text-blue-600 dark:text-blue-400 hover:underline break-all"
            onclick="event.stopPropagation()"
          >${file.public_url}</a>
        </div>

        <div>
          <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-1">Uploaded</label>
          <p class="text-sm text-zinc-500 dark:text-zinc-400">${file.uploadedAt}</p>
        </div>

        <!-- Editable Fields -->
        <form hx-put="/admin/media/${file.id}" hx-target="#file-modal-content" class="space-y-4">
          <div>
            <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-1">Alt Text</label>
            <input
              type="text"
              name="alt"
              value="${file.alt || ''}"
              class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white placeholder-zinc-500 dark:placeholder-zinc-400 ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-blue-600 dark:focus:ring-blue-500 focus:outline-none transition-colors"
              placeholder="Describe this image..."
            >
          </div>

          <div>
            <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-1">Caption</label>
            <textarea
              name="caption"
              rows="3"
              class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white placeholder-zinc-500 dark:placeholder-zinc-400 ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-blue-600 dark:focus:ring-blue-500 focus:outline-none transition-colors"
              placeholder="Optional caption..."
            >${file.caption || ''}</textarea>
          </div>

          <div>
            <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-1">Tags</label>
            <input
              type="text"
              name="tags"
              value="${file.tags.join(', ')}"
              class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white placeholder-zinc-500 dark:placeholder-zinc-400 ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-blue-600 dark:focus:ring-blue-500 focus:outline-none transition-colors"
              placeholder="tag1, tag2, tag3"
            >
          </div>

          <div class="flex justify-between">
            <button
              type="submit"
              class="rounded-lg bg-green-600 px-4 py-2 text-sm font-semibold text-white hover:bg-green-700 transition-colors"
            >
              Save Changes
            </button>
            <button
              type="button"
              hx-delete="/admin/media/${file.id}"
              hx-confirm="Are you sure you want to delete this file?"
              hx-target="body"
              class="rounded-lg bg-red-600 px-4 py-2 text-sm font-semibold text-white hover:bg-red-700 transition-colors"
            >
              Delete File
            </button>
          </div>
        </form>
      </div>
    </div>
  `
}