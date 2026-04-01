import manifest from '../manifest.json'
import type {
  QRCode,
  CreateQRCodeInput,
  UpdateQRCodeInput,
  QRCodeGenerateOptions,
  QRCodeGenerateResult,
  QRCodeOperationResult,
  QRGeneratorSettings,
  ErrorCorrectionLevel,
  CornerShape,
  DotShape,
  DpiOption,
  PngExportResult
} from '../types'
import type { D1Database } from '@cloudflare/workers-types'
import { normalizeHexColor, isValidHexColor } from '../utils/color-validator'
import { validateDestinationUrl } from '../utils/url-validator'
import { getContrastWarning } from '../utils/contrast-checker'
import { generateUniqueShortCode } from '../utils/short-code'
import { SvgCustomizer } from './svg-customizer'
import { LogoEmbedder } from './logo-embedder'
import { PngExporter } from './png-exporter'
import { RedirectIntegration, MatchType } from './redirect-integration'
import QRCodeLib from 'qrcode-svg'

/**
 * QR Code Generation and Management Service
 * Handles CRUD operations for QR codes and SVG generation with qrcode-svg library
 * Phase 2: Supports shape customization, logo embedding, and PNG export
 * Phase 3: Integrates with redirect-management for trackable short URLs
 */
export class QRService {
  private svgCustomizer = new SvgCustomizer()
  private logoEmbedder = new LogoEmbedder()
  private pngExporter = new PngExporter()
  private redirectIntegration: RedirectIntegration

  constructor(private db: D1Database) {
    this.redirectIntegration = new RedirectIntegration(db)
  }

  /**
   * Get plugin settings from the database
   */
  async getSettings(): Promise<{ status: string; data: QRGeneratorSettings }> {
    try {
      const record = await this.db
        .prepare(`SELECT settings, status FROM plugins WHERE id = ?`)
        .bind(manifest.id)
        .first()

      if (!record) {
        return {
          status: 'inactive',
          data: this.getDefaultSettings()
        }
      }

      return {
        status: (record?.status as string) || 'inactive',
        data: record?.settings ? JSON.parse(record.settings as string) : this.getDefaultSettings()
      }
    } catch (error) {
      console.error('[QRService] Error getting settings:', error)
      return {
        status: 'inactive',
        data: this.getDefaultSettings()
      }
    }
  }

  /**
   * Get default plugin settings
   */
  getDefaultSettings(): QRGeneratorSettings {
    return {
      enabled: true,
      defaultForegroundColor: '#000000',
      defaultBackgroundColor: '#ffffff',
      defaultErrorCorrection: 'M',
      defaultSize: 300,
      defaultCornerShape: 'square',
      defaultDotShape: 'square',
      defaultLogoUrl: ''
    }
  }

  /**
   * Save plugin settings to the database
   */
  async saveSettings(settings: QRGeneratorSettings): Promise<void> {
    try {
      console.log('[QRService] Saving settings for plugin:', manifest.id)
      console.log('[QRService] Settings:', JSON.stringify(settings))

      // Check if plugin row exists
      const existing = await this.db
        .prepare(`SELECT id, status FROM plugins WHERE id = ?`)
        .bind(manifest.id)
        .first()

      if (existing) {
        // Update existing row
        const result = await this.db
          .prepare(`UPDATE plugins SET settings = ?, last_updated = ? WHERE id = ?`)
          .bind(JSON.stringify(settings), Date.now(), manifest.id)
          .run()
        console.log('[QRService] Settings updated successfully')
      } else {
        // Insert new row
        const result = await this.db
          .prepare(`
            INSERT INTO plugins (id, name, display_name, description, version, author, category, status, settings, installed_at, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'inactive', ?, ?, ?)
          `)
          .bind(
            manifest.id,
            manifest.id,
            manifest.name,
            manifest.description || '',
            manifest.version || '1.0.0',
            manifest.author || 'Unknown',
            manifest.category || 'utilities',
            JSON.stringify(settings),
            Date.now(),
            Date.now()
          )
          .run()
        console.log('[QRService] Settings inserted successfully')
      }
    } catch (error) {
      console.error('[QRService] Error saving settings:', error)
      throw new Error(`Failed to save QR generator settings: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  // QR Code Generation

  /**
   * Generate QR code SVG from content with customizable options
   * Returns both raw SVG string and data URL
   *
   * Phase 2: Supports shape customization and logo embedding
   * - Uses join:false when shapes/eyeColor needed (individual rects for manipulation)
   * - Uses join:true when no customization (optimized paths)
   * - Forces Level H error correction when logo is present
   */
  generate(options: QRCodeGenerateOptions): QRCodeGenerateResult {
    const {
      content,
      size = 300,
      foregroundColor = '#000000',
      backgroundColor = '#ffffff',
      errorCorrection = 'M',
      // Phase 2 options
      cornerShape = 'square',
      dotShape = 'square',
      eyeColor = null,
      logoUrl = null,
      logoAspectRatio = null
    } = options

    // Validate colors
    const normalizedFg = normalizeHexColor(foregroundColor)
    const normalizedBg = normalizeHexColor(backgroundColor)

    if (!normalizedFg || !normalizedBg) {
      throw new Error('Invalid hex color format. Use #RRGGBB or #RGB format.')
    }

    // Determine if we need custom shapes or eye color
    const needsCustomization = cornerShape !== 'square' ||
                                dotShape !== 'square' ||
                                eyeColor !== null

    // Force Level H when logo is present (STYLE-04)
    const effectiveErrorCorrection = logoUrl ? 'H' : errorCorrection

    // Generate QR code using qrcode-svg library
    // padding: 4 provides the required 4-module quiet zone per ISO 18004
    // Use join:false when customization is needed (individual rects)
    // Use join:true when no customization (optimized paths)
    console.log('[QRService.generate] Creating QR with options:', {
      content,
      padding: 4,
      width: size,
      height: size,
      color: normalizedFg,
      background: normalizedBg,
      ecl: effectiveErrorCorrection,
      join: !needsCustomization
    })

    const qr = new QRCodeLib({
      content: content,
      padding: 4,
      width: size,
      height: size,
      color: normalizedFg,
      background: normalizedBg,
      ecl: effectiveErrorCorrection as 'L' | 'M' | 'Q' | 'H',
      join: !needsCustomization  // false when shapes/eyeColor needed
    })

    console.log('[QRService.generate] QR object created, typeof qr.svg:', typeof qr.svg)
    let svg = qr.svg()
    console.log('[QRService.generate] SVG generated, length:', svg?.length, 'first 200 chars:', svg?.substring(0, 200))

    // Apply shape customization if needed (STYLE-05, STYLE-06, STYLE-07)
    console.log('[QRService.generate] needsCustomization:', needsCustomization, { cornerShape, dotShape, eyeColor })
    if (needsCustomization) {
      console.log('[QRService.generate] Calling svgCustomizer.customize')
      svg = this.svgCustomizer.customize(svg, {
        cornerShape,
        dotShape,
        eyeColor: eyeColor ?? undefined,
        moduleColor: normalizedFg
      })
      console.log('[QRService.generate] After customize, length:', svg?.length)
    }

    // Embed logo if provided (STYLE-03)
    console.log('[QRService.generate] logoUrl:', logoUrl ? 'present' : 'null', 'logoAspectRatio:', logoAspectRatio)
    if (logoUrl && logoAspectRatio) {
      console.log('[QRService.generate] Calling logoEmbedder.embed')
      svg = this.logoEmbedder.embed(svg, {
        logoDataUrl: logoUrl,
        logoAspectRatio
      })
      console.log('[QRService.generate] After logo embed, length:', svg?.length)
    }

    console.log('[QRService.generate] Final SVG length:', svg?.length, 'first 300 chars:', svg?.substring(0, 300))
    // Create data URL for direct embedding
    const dataUrl = `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`

    return {
      svg,
      dataUrl
    }
  }

  // PNG Export Methods

  /**
   * Generate QR code as PNG
   * Combines SVG generation with PNG conversion using @cf-wasm/resvg
   *
   * @param options - Generation options including PNG-specific settings
   * @returns PNG buffer and metadata
   */
  async generatePng(options: QRCodeGenerateOptions & {
    dpi?: DpiOption
    transparent?: boolean
  }): Promise<PngExportResult> {
    // First generate the SVG
    const { svg } = this.generate(options)

    // Then convert to PNG
    const result = await this.pngExporter.export(svg, {
      dpi: options.dpi ?? 300,
      baseSize: options.size ?? 300,
      transparent: options.transparent ?? false
    })

    return {
      buffer: result.buffer,
      width: result.width,
      height: result.height,
      size: result.size,
      contentType: 'image/png' as const
    }
  }

  /**
   * Generate PNG for a stored QR code record
   * Retrieves QR code from database and generates PNG with specified options
   *
   * @param id - QR code record ID
   * @param dpi - Output DPI (72, 150, or 300)
   * @param transparent - Enable transparent background
   * @returns PNG buffer or error
   */
  async generateForRecordAsPng(
    id: string,
    dpi: DpiOption = 300,
    transparent: boolean = false,
    baseUrl?: string  // Base URL for constructing short URL
  ): Promise<{ success: boolean; result?: PngExportResult; error?: string; warning?: string }> {
    const qrCode = await this.getById(id)
    if (!qrCode) {
      return { success: false, error: 'QR code not found' }
    }

    // Check size warning
    const warning = PngExporter.checkSizeWarning(qrCode.size, dpi)

    // Only use eye color if it's different from foreground color
    const effectiveEyeColor = (qrCode.eyeColor && qrCode.eyeColor !== qrCode.foregroundColor)
      ? qrCode.eyeColor
      : null

    // QR code encodes the short URL (for tracking), not the destination URL
    const content = baseUrl && qrCode.shortCode
      ? `${baseUrl}/qr/${qrCode.shortCode}`
      : qrCode.destinationUrl  // Fallback if no baseUrl provided

    try {
      const result = await this.generatePng({
        content,
        size: qrCode.size,
        foregroundColor: qrCode.foregroundColor,
        backgroundColor: qrCode.backgroundColor,
        errorCorrection: qrCode.errorCorrection,
        cornerShape: qrCode.cornerShape,
        dotShape: qrCode.dotShape,
        eyeColor: effectiveEyeColor,
        logoUrl: qrCode.logoUrl,
        logoAspectRatio: qrCode.logoAspectRatio,
        dpi,
        transparent
      })

      return {
        success: true,
        result,
        warning: warning ?? undefined
      }
    } catch (error) {
      return {
        success: false,
        error: `PNG generation failed: ${error instanceof Error ? error.message : String(error)}`
      }
    }
  }

  /**
   * Get estimated PNG size for a QR code
   * Useful for UI to warn users before generating large files
   *
   * @param size - Base QR code size in pixels
   * @param dpi - Target DPI
   * @returns Estimated size in bytes and optional warning message
   */
  estimatePngSize(size: number, dpi: DpiOption): { bytes: number; warning: string | null } {
    return {
      bytes: PngExporter.estimateSize(size, dpi),
      warning: PngExporter.checkSizeWarning(size, dpi)
    }
  }

  // CRUD Operations

  /**
   * Create a new QR code with validation
   * Phase 2: Supports shape customization and logo embedding with automatic error correction
   * Phase 3: Atomically creates QR code and redirect entry via D1 batch()
   */
  async create(input: CreateQRCodeInput, userId: string): Promise<QRCodeOperationResult> {
    try {
      // Validate destination URL
      const urlValidation = validateDestinationUrl(input.destinationUrl)
      if (!urlValidation.valid) {
        return {
          success: false,
          qrCode: undefined,
          error: urlValidation.error
        }
      }

      // Get default settings
      const { data: settings } = await this.getSettings()

      // Apply defaults
      const foregroundColor = input.foregroundColor ?? settings.defaultForegroundColor
      const backgroundColor = input.backgroundColor ?? settings.defaultBackgroundColor
      let errorCorrection = input.errorCorrection ?? settings.defaultErrorCorrection
      const size = input.size ?? settings.defaultSize

      // Phase 2: Shape defaults
      const cornerShape = input.cornerShape ?? (settings.defaultCornerShape || 'square')
      const dotShape = input.dotShape ?? (settings.defaultDotShape || 'square')

      // Validate and normalize colors
      const normalizedFg = normalizeHexColor(foregroundColor)
      const normalizedBg = normalizeHexColor(backgroundColor)

      if (!normalizedFg) {
        return {
          success: false,
          qrCode: undefined,
          error: `Invalid foreground color: ${foregroundColor}. Use #RRGGBB or #RGB format.`
        }
      }

      if (!normalizedBg) {
        return {
          success: false,
          qrCode: undefined,
          error: `Invalid background color: ${backgroundColor}. Use #RRGGBB or #RGB format.`
        }
      }

      // Validate eye color if provided
      let normalizedEyeColor: string | null = null
      if (input.eyeColor) {
        normalizedEyeColor = normalizeHexColor(input.eyeColor)
        if (!normalizedEyeColor) {
          return {
            success: false,
            qrCode: undefined,
            error: `Invalid eye color: ${input.eyeColor}. Use #RRGGBB or #RGB format.`
          }
        }
      }

      // Check contrast ratio
      const contrastWarning = getContrastWarning(normalizedFg, normalizedBg)

      // Phase 2: Handle error correction with logo (STYLE-04)
      let errorCorrectionBeforeLogo: ErrorCorrectionLevel | null = null
      if (input.logoUrl) {
        // Store original before forcing H
        if (errorCorrection !== 'H') {
          errorCorrectionBeforeLogo = errorCorrection
        }
        errorCorrection = 'H'  // Force Level H with logo
      }

      // Generate unique ID and use provided short code or generate new one
      const id = crypto.randomUUID()
      const shortCode = input.shortCode || await generateUniqueShortCode(this.db)
      const redirectId = crypto.randomUUID()
      const now = Date.now()

      // Phase 3: Atomically insert QR code AND redirect via D1 batch()
      // This ensures both records are created together or neither is created
      await this.db.batch([
        this.db
          .prepare(`
            INSERT INTO qr_codes (
              id, name, destination_url, foreground_color, background_color,
              error_correction, size, corner_shape, dot_shape, eye_color,
              logo_url, logo_aspect_ratio, error_correction_before_logo,
              short_code, created_by, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `)
          .bind(
            id,
            input.name ?? null,
            urlValidation.normalizedUrl!,
            normalizedFg,
            normalizedBg,
            errorCorrection,
            size,
            cornerShape,
            dotShape,
            normalizedEyeColor,
            input.logoUrl ?? null,
            input.logoAspectRatio ?? null,
            errorCorrectionBeforeLogo,
            shortCode,
            userId,
            now,
            now
          ),
        this.db
          .prepare(`
            INSERT INTO redirects (
              id, source, destination, match_type, status_code,
              is_active, source_plugin, created_by, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `)
          .bind(
            redirectId,
            this.redirectIntegration.getSourcePath(shortCode),
            urlValidation.normalizedUrl!,
            MatchType.EXACT,
            302,  // Temporary redirect - destination may change
            1,    // is_active = true
            'qr-generator',
            userId,
            now,
            now
          )
      ])

      // Invalidate redirect cache after successful insert
      this.redirectIntegration.invalidateCache()

      // Fetch the created QR code
      const qrCode = await this.getById(id)

      return {
        success: true,
        qrCode: qrCode!,
        error: undefined,
        warning: contrastWarning ?? undefined
      }
    } catch (error) {
      console.error('[QRService] Error creating QR code:', error)
      return {
        success: false,
        qrCode: undefined,
        error: `Failed to create QR code: ${error instanceof Error ? error.message : String(error)}`
      }
    }
  }

  /**
   * Get QR code by ID
   * Phase 3: Includes scan count from redirect analytics
   */
  async getById(id: string): Promise<QRCode | null> {
    try {
      // Phase 3: Join with redirects and redirect_analytics to get scan count
      const row = await this.db
        .prepare(`
          SELECT
            q.id, q.name, q.destination_url, q.foreground_color, q.background_color,
            q.error_correction, q.size, q.corner_shape, q.dot_shape, q.eye_color,
            q.logo_url, q.logo_aspect_ratio, q.error_correction_before_logo,
            q.short_code, q.created_by, q.created_at, q.updated_at, q.deleted_at,
            COALESCE(a.hit_count, 0) as scan_count
          FROM qr_codes q
          LEFT JOIN redirects r ON r.source = '/qr/' || q.short_code AND r.deleted_at IS NULL
          LEFT JOIN redirect_analytics a ON r.id = a.redirect_id
          WHERE q.id = ? AND q.deleted_at IS NULL
        `)
        .bind(id)
        .first()

      if (!row) {
        return null
      }

      return this.mapRowToQRCode(row)
    } catch (error) {
      console.error('[QRService] Error getting QR code by ID:', error)
      return null
    }
  }

  /**
   * List all QR codes with optional pagination
   * Phase 3: Includes scan counts from redirect analytics via JOIN
   */
  async list(options?: { limit?: number; offset?: number; search?: string }): Promise<QRCode[]> {
    try {
      const limit = options?.limit ?? 50
      const offset = options?.offset ?? 0
      const search = options?.search

      // Phase 3: Join with redirects and redirect_analytics to get scan counts
      // - LEFT JOIN redirects on source = '/qr/' || short_code (only active redirects)
      // - LEFT JOIN redirect_analytics to get hit_count
      // - COALESCE to return 0 when no analytics exist
      let query = `
        SELECT
          q.id, q.name, q.destination_url, q.foreground_color, q.background_color,
          q.error_correction, q.size, q.corner_shape, q.dot_shape, q.eye_color,
          q.logo_url, q.logo_aspect_ratio, q.error_correction_before_logo,
          q.short_code, q.created_by, q.created_at, q.updated_at, q.deleted_at,
          COALESCE(a.hit_count, 0) as scan_count
        FROM qr_codes q
        LEFT JOIN redirects r ON r.source = '/qr/' || q.short_code AND r.deleted_at IS NULL
        LEFT JOIN redirect_analytics a ON r.id = a.redirect_id
        WHERE q.deleted_at IS NULL
      `

      const bindings: any[] = []

      if (search) {
        query += ` AND (q.name LIKE ? OR q.destination_url LIKE ?)`
        const searchPattern = `%${search}%`
        bindings.push(searchPattern, searchPattern)
      }

      query += ` ORDER BY q.created_at DESC LIMIT ? OFFSET ?`
      bindings.push(limit, offset)

      const result = await this.db.prepare(query).bind(...bindings).all()

      return result.results.map(row => this.mapRowToQRCode(row))
    } catch (error) {
      console.error('[QRService] Error listing QR codes:', error)
      return []
    }
  }

  /**
   * Count QR codes (for pagination)
   */
  async count(options?: { search?: string }): Promise<number> {
    try {
      let query = `SELECT COUNT(*) as count FROM qr_codes WHERE deleted_at IS NULL`
      const bindings: any[] = []

      if (options?.search) {
        query += ` AND (name LIKE ? OR destination_url LIKE ?)`
        const searchPattern = `%${options.search}%`
        bindings.push(searchPattern, searchPattern)
      }

      const result = await this.db.prepare(query).bind(...bindings).first()

      return (result?.count as number) ?? 0
    } catch (error) {
      console.error('[QRService] Error counting QR codes:', error)
      return 0
    }
  }

  /**
   * Update an existing QR code
   * Phase 2: Supports shape customization and logo embedding with error correction restoration
   * Phase 3: Atomically updates redirect when destination URL changes
   */
  async update(id: string, input: UpdateQRCodeInput, userId?: string): Promise<QRCodeOperationResult> {
    try {
      // Fetch existing QR code
      const existing = await this.getById(id)
      if (!existing) {
        return {
          success: false,
          qrCode: undefined,
          error: 'QR code not found'
        }
      }

      // Validate destination URL if provided
      let normalizedDestinationUrl: string | undefined
      if (input.destinationUrl) {
        const urlValidation = validateDestinationUrl(input.destinationUrl)
        if (!urlValidation.valid) {
          return {
            success: false,
            qrCode: undefined,
            error: urlValidation.error
          }
        }
        normalizedDestinationUrl = urlValidation.normalizedUrl!
      }

      // Build update query dynamically based on provided fields
      const updates: string[] = []
      const bindings: any[] = []

      if (input.name !== undefined) {
        updates.push('name = ?')
        bindings.push(input.name)
      }

      if (input.destinationUrl !== undefined) {
        updates.push('destination_url = ?')
        bindings.push(normalizedDestinationUrl!)
      }

      if (input.foregroundColor !== undefined) {
        const normalized = normalizeHexColor(input.foregroundColor)
        if (!normalized) {
          return {
            success: false,
            qrCode: undefined,
            error: `Invalid foreground color: ${input.foregroundColor}`
          }
        }
        updates.push('foreground_color = ?')
        bindings.push(normalized)
      }

      if (input.backgroundColor !== undefined) {
        const normalized = normalizeHexColor(input.backgroundColor)
        if (!normalized) {
          return {
            success: false,
            qrCode: undefined,
            error: `Invalid background color: ${input.backgroundColor}`
          }
        }
        updates.push('background_color = ?')
        bindings.push(normalized)
      }

      if (input.errorCorrection !== undefined) {
        updates.push('error_correction = ?')
        bindings.push(input.errorCorrection)
      }

      if (input.size !== undefined) {
        updates.push('size = ?')
        bindings.push(input.size)
      }

      // Phase 2: Handle shape updates
      if (input.cornerShape !== undefined) {
        updates.push('corner_shape = ?')
        bindings.push(input.cornerShape)
      }

      if (input.dotShape !== undefined) {
        updates.push('dot_shape = ?')
        bindings.push(input.dotShape)
      }

      if (input.eyeColor !== undefined) {
        const normalizedEyeColor = input.eyeColor ? normalizeHexColor(input.eyeColor) : null
        if (input.eyeColor && !normalizedEyeColor) {
          return {
            success: false,
            qrCode: undefined,
            error: `Invalid eye color: ${input.eyeColor}`
          }
        }
        updates.push('eye_color = ?')
        bindings.push(normalizedEyeColor)
      }

      // Phase 2: Handle logo addition/removal (STYLE-04)
      if (input.logoUrl !== undefined) {
        if (input.logoUrl) {
          // Adding logo - enforce Level H
          if (existing.errorCorrection !== 'H') {
            updates.push('error_correction_before_logo = ?')
            bindings.push(existing.errorCorrection)
            updates.push('error_correction = ?')
            bindings.push('H')
          }
        } else {
          // Removing logo - restore previous level if available
          if (existing.errorCorrectionBeforeLogo) {
            updates.push('error_correction = ?')
            bindings.push(existing.errorCorrectionBeforeLogo)
          }
          updates.push('error_correction_before_logo = ?')
          bindings.push(null)
        }
        updates.push('logo_url = ?')
        bindings.push(input.logoUrl)
      }

      // Handle logo aspect ratio
      if (input.logoAspectRatio !== undefined) {
        updates.push('logo_aspect_ratio = ?')
        bindings.push(input.logoAspectRatio)
      }

      // Always update updated_at
      const now = Date.now()
      updates.push('updated_at = ?')
      bindings.push(now)

      // Add ID to bindings
      bindings.push(id)

      if (updates.length === 1) {
        // Only updated_at would change, nothing to do
        return {
          success: true,
          qrCode: existing,
          error: undefined
        }
      }

      // Phase 3: If destination URL is being updated and QR has a short code,
      // atomically update both QR code and redirect
      if (normalizedDestinationUrl && existing.shortCode) {
        const sourcePath = this.redirectIntegration.getSourcePath(existing.shortCode)
        await this.db.batch([
          this.db
            .prepare(`UPDATE qr_codes SET ${updates.join(', ')} WHERE id = ?`)
            .bind(...bindings),
          this.db
            .prepare(`UPDATE redirects SET destination = ?, updated_at = ? WHERE source = ? AND deleted_at IS NULL`)
            .bind(normalizedDestinationUrl, now, sourcePath)
        ])
        // Invalidate redirect cache
        this.redirectIntegration.invalidateCache()
      } else {
        // No redirect update needed - just update QR code
        await this.db
          .prepare(`UPDATE qr_codes SET ${updates.join(', ')} WHERE id = ?`)
          .bind(...bindings)
          .run()
      }

      // Fetch updated QR code
      const updated = await this.getById(id)

      // Check contrast ratio if colors were updated
      let contrastWarning: string | undefined
      if (updated && (input.foregroundColor || input.backgroundColor)) {
        const warning = getContrastWarning(updated.foregroundColor, updated.backgroundColor)
        contrastWarning = warning ?? undefined
      }

      return {
        success: true,
        qrCode: updated!,
        error: undefined,
        warning: contrastWarning
      }
    } catch (error) {
      console.error('[QRService] Error updating QR code:', error)
      return {
        success: false,
        qrCode: undefined,
        error: `Failed to update QR code: ${error instanceof Error ? error.message : String(error)}`
      }
    }
  }

  /**
   * Delete a QR code (soft delete - sets deleted_at timestamp)
   * Phase 3: Atomically soft-deletes both QR code and associated redirect
   */
  async delete(id: string): Promise<QRCodeOperationResult> {
    try {
      // First fetch the QR code to get its short code
      const existing = await this.getById(id)
      if (!existing) {
        return {
          success: false,
          qrCode: undefined,
          error: 'QR code not found'
        }
      }

      const now = Date.now()

      // Phase 3: Atomically soft-delete both QR code and redirect
      if (existing.shortCode) {
        const sourcePath = this.redirectIntegration.getSourcePath(existing.shortCode)
        await this.db.batch([
          this.db
            .prepare(`UPDATE qr_codes SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL`)
            .bind(now, id),
          this.db
            .prepare(`UPDATE redirects SET deleted_at = ? WHERE source = ? AND deleted_at IS NULL`)
            .bind(now, sourcePath)
        ])
        // Invalidate redirect cache
        this.redirectIntegration.invalidateCache()
      } else {
        // No short code (legacy QR code) - just delete QR code
        await this.db
          .prepare(`UPDATE qr_codes SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL`)
          .bind(now, id)
          .run()
      }

      return {
        success: true,
        qrCode: undefined,
        error: undefined
      }
    } catch (error) {
      console.error('[QRService] Error deleting QR code:', error)
      return {
        success: false,
        qrCode: undefined,
        error: `Failed to delete QR code: ${error instanceof Error ? error.message : String(error)}`
      }
    }
  }

  /**
   * Map database row to QRCode type
   * @internal Helper method for type conversion
   * Phase 2: Includes shape and logo fields
   * Phase 3: Includes shortCode and scanCount for redirect integration
   */
  private mapRowToQRCode(row: any): QRCode {
    return {
      id: row.id as string,
      name: row.name as string | null,
      destinationUrl: row.destination_url as string,
      foregroundColor: row.foreground_color as string,
      backgroundColor: row.background_color as string,
      errorCorrection: row.error_correction as ErrorCorrectionLevel,
      size: row.size as number,
      // Phase 2 fields
      cornerShape: (row.corner_shape as CornerShape) || 'square',
      dotShape: (row.dot_shape as DotShape) || 'square',
      eyeColor: row.eye_color as string | null,
      logoUrl: row.logo_url as string | null,
      logoAspectRatio: row.logo_aspect_ratio as number | null,
      errorCorrectionBeforeLogo: row.error_correction_before_logo as ErrorCorrectionLevel | null,
      // Phase 3 fields
      shortCode: row.short_code as string,
      // scanCount from redirect_analytics JOIN (optional, only present after list/getById queries)
      scanCount: row.scan_count !== undefined ? (row.scan_count as number) : undefined,
      createdBy: row.created_by as string,
      createdAt: row.created_at as number,
      updatedAt: row.updated_at as number,
      deletedAt: row.deleted_at as number | null
    }
  }

  // Lifecycle methods

  /**
   * Install the plugin (create database entry)
   */
  async install(): Promise<void> {
    try {
      const defaultSettings = this.getDefaultSettings()
      await this.db
        .prepare(`
          INSERT INTO plugins (
            id, name, display_name, description, version, author,
            category, status, settings, installed_at, last_updated
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, 'inactive', ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            display_name = excluded.display_name,
            description = excluded.description,
            version = excluded.version,
            updated_at = excluded.last_updated
        `)
        .bind(
          manifest.id,
          manifest.id,
          manifest.name,
          manifest.description,
          manifest.version,
          manifest.author,
          manifest.category,
          JSON.stringify(defaultSettings),
          Date.now(),
          Date.now()
        )
        .run()
      console.log('[QRService] Plugin installed successfully')
    } catch (error) {
      console.error('[QRService] Error installing plugin:', error)
      throw new Error('Failed to install QR generator plugin')
    }
  }

  /**
   * Activate the plugin
   */
  async activate(): Promise<void> {
    try {
      await this.db
        .prepare(`
          UPDATE plugins
          SET status = 'active', last_updated = ?
          WHERE id = ?
        `)
        .bind(Date.now(), manifest.id)
        .run()
      console.log('[QRService] Plugin activated')
    } catch (error) {
      console.error('[QRService] Error activating plugin:', error)
      throw new Error('Failed to activate QR generator plugin')
    }
  }

  /**
   * Deactivate the plugin
   */
  async deactivate(): Promise<void> {
    try {
      await this.db
        .prepare(`
          UPDATE plugins
          SET status = 'inactive', last_updated = ?
          WHERE id = ?
        `)
        .bind(Date.now(), manifest.id)
        .run()
      console.log('[QRService] Plugin deactivated')
    } catch (error) {
      console.error('[QRService] Error deactivating plugin:', error)
      throw new Error('Failed to deactivate QR generator plugin')
    }
  }

  /**
   * Uninstall the plugin (remove database entry)
   */
  async uninstall(): Promise<void> {
    try {
      await this.db
        .prepare(`DELETE FROM plugins WHERE id = ?`)
        .bind(manifest.id)
        .run()
      console.log('[QRService] Plugin uninstalled')
    } catch (error) {
      console.error('[QRService] Error uninstalling plugin:', error)
      throw new Error('Failed to uninstall QR generator plugin')
    }
  }
}
