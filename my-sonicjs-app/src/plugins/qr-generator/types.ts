// Error correction levels per ISO 18004
export type ErrorCorrectionLevel = 'L' | 'M' | 'Q' | 'H'

// Corner shape options for position detection patterns (eyes)
// STYLE-05: square, rounded, dots, extra-rounded
export type CornerShape = 'square' | 'rounded' | 'dots' | 'extra-rounded'

// Dot shape options for data modules
// STYLE-06: square, rounded, dots, diamond
export type DotShape = 'square' | 'rounded' | 'dots' | 'diamond'

// DPI options for PNG export (EXP-01)
// 72 = web/screen, 150 = standard print, 300 = high-quality print
export type DpiOption = 72 | 150 | 300

// Export format options
export type ExportFormat = 'svg' | 'png'

// QR code stored in database
export interface QRCode {
  id: string
  name: string | null
  destinationUrl: string
  foregroundColor: string  // Hex, e.g., "#000000"
  backgroundColor: string  // Hex, e.g., "#ffffff"
  errorCorrection: ErrorCorrectionLevel
  size: number  // Pixels, e.g., 300
  // Phase 2: Shape customization
  cornerShape: CornerShape
  dotShape: DotShape
  eyeColor: string | null  // Hex color for position markers, null = use foregroundColor
  // Phase 2: Logo embedding
  logoUrl: string | null  // URL/data URL of embedded logo
  logoAspectRatio: number | null  // Cached aspect ratio for positioning
  errorCorrectionBeforeLogo: ErrorCorrectionLevel | null  // Backup for restoration
  // Phase 3: Redirect integration
  shortCode: string  // 6-character alphanumeric code for redirect path /qr/{code}
  /**
   * Number of times QR code has been scanned (from redirect analytics)
   * Populated when listing QR codes, not stored in qr_codes table
   */
  scanCount?: number
  createdBy: string
  createdAt: number  // Unix timestamp ms
  updatedAt: number
  deletedAt: number | null
}

// Input for creating a new QR code
export interface CreateQRCodeInput {
  name?: string | null
  destinationUrl: string
  foregroundColor?: string  // Default: #000000
  backgroundColor?: string  // Default: #ffffff
  errorCorrection?: ErrorCorrectionLevel  // Default: M
  size?: number  // Default: 300
  // Phase 2: Shape customization
  cornerShape?: CornerShape  // Default: square
  dotShape?: DotShape  // Default: square
  eyeColor?: string | null  // Default: null (uses foregroundColor)
  // Phase 2: Logo embedding
  logoUrl?: string | null
  logoAspectRatio?: number | null
  // Phase 3: Redirect integration - optional, will be generated if not provided
  shortCode?: string  // 6-character alphanumeric code for redirect path /qr/{code}
}

// Input for updating existing QR code
export interface UpdateQRCodeInput {
  name?: string | null
  destinationUrl?: string
  foregroundColor?: string
  backgroundColor?: string
  errorCorrection?: ErrorCorrectionLevel
  size?: number
  // Phase 2: Shape customization
  cornerShape?: CornerShape
  dotShape?: DotShape
  eyeColor?: string | null
  // Phase 2: Logo embedding
  logoUrl?: string | null
  logoAspectRatio?: number | null
}

// Options for PNG export
export interface PngExportOptions {
  /** DPI for output image (72 = web, 150 = screen, 300 = print) */
  dpi?: DpiOption
  /** Enable transparent background */
  transparent?: boolean
}

// Result of PNG export
export interface PngExportResult {
  /** PNG image as Uint8Array */
  buffer: Uint8Array
  /** Width of output image in pixels */
  width: number
  /** Height of output image in pixels */
  height: number
  /** File size in bytes */
  size: number
  /** Content type for HTTP response */
  contentType: 'image/png'
}

// Options for generating QR code image
export interface QRCodeGenerateOptions {
  content: string
  size?: number
  foregroundColor?: string
  backgroundColor?: string
  errorCorrection?: ErrorCorrectionLevel
  format?: 'svg' | 'dataUrl'
  // Shape customization
  cornerShape?: CornerShape
  dotShape?: DotShape
  eyeColor?: string | null
  // Logo embedding
  logoUrl?: string | null
  logoAspectRatio?: number | null
  // PNG export options
  exportFormat?: ExportFormat
  pngOptions?: PngExportOptions
}

// Result of QR code generation
export interface QRCodeGenerateResult {
  svg: string  // Raw SVG string
  dataUrl: string  // data:image/svg+xml;base64,...
  // PNG data (only present if exportFormat === 'png')
  png?: PngExportResult
}

// Result of CRUD operations
export interface QRCodeOperationResult {
  success: boolean
  qrCode?: QRCode
  error?: string
  warning?: string  // e.g., low contrast warning
}

// Plugin settings
export interface QRGeneratorSettings {
  enabled: boolean
  defaultForegroundColor: string
  defaultBackgroundColor: string
  defaultErrorCorrection: ErrorCorrectionLevel
  defaultSize: number
  // Default shape settings
  defaultCornerShape?: CornerShape
  defaultDotShape?: DotShape
  // Default logo
  defaultLogoUrl?: string  // Data URL or image URL for default logo
}
