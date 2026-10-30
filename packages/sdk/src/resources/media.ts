import { type HttpClient } from '../http'
import { type RequestAuth } from '../config'
import { type MediaAsset } from '../types'

export class MediaResource {
  constructor(private http: HttpClient) {}

  upload(
    file: File | Blob,
    o?: { folder?: string; filename?: string },
    auth?: RequestAuth,
  ) {
    const fd = new FormData()
    fd.append('file', file, o?.filename)
    if (o?.folder) fd.append('folder', o.folder)
    return this.http.request<{ success: boolean; file: MediaAsset }>(
      'POST',
      '/api/media/upload',
      { form: fd, auth },
    )
  }

  uploadMany(
    files: (File | Blob)[],
    o?: { folder?: string },
    auth?: RequestAuth,
  ) {
    const fd = new FormData()
    for (const f of files) fd.append('files', f)
    if (o?.folder) fd.append('folder', o.folder)
    return this.http.request<{
      success: boolean
      uploaded: MediaAsset[]
      errors: unknown[]
      summary: { total: number; successful: number; failed: number }
    }>('POST', '/api/media/upload-multiple', { form: fd, auth })
  }

  bulkDelete(fileIds: string[], auth?: RequestAuth) {
    return this.http.request<{ success: boolean; deleted: string[]; errors: unknown[] }>(
      'POST',
      '/api/media/bulk-delete',
      { body: { fileIds }, auth },
    )
  }
}
