// Error correction levels per ISO 18004
export type ErrorCorrectionLevel = 'L' | 'M' | 'Q' | 'H'

// Corner shape options for position detection patterns (eyes)
// STYLE-05: square, rounded, dots, extra-rounded
export type CornerShape = 'square' | 'rounded' | 'dots' | 'extra-rounded'

// Dot shape options for data modules
// STYLE-06: square, rounded, dots, diamond
export type DotShape = 'square' | 'rounded' | 'dots' | 'diamond'

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

// Options for generating QR code image
export interface QRCodeGenerateOptions {
  content: string
  size?: number
  foregroundColor?: string
  backgroundColor?: string
  errorCorrection?: ErrorCorrectionLevel
  format?: 'svg' | 'dataUrl'
  // Phase 2: Shape customization
  cornerShape?: CornerShape
  dotShape?: DotShape
  eyeColor?: string | null
  // Phase 2: Logo embedding
  logoUrl?: string | null
  logoAspectRatio?: number | null
}

// Result of QR code generation
export interface QRCodeGenerateResult {
  svg: string  // Raw SVG string
  dataUrl: string  // data:image/svg+xml;base64,...
}

// Result of CRUD operations
export interface QRCodeOperationResult {
  success: boolean
  qrCode?: QRCode
  error?: string
  warning?: string  // e.g., low contrast warning
}

// Plugin settings (for Phase 5)
export interface QRGeneratorSettings {
  defaultForegroundColor: string
  defaultBackgroundColor: string
  defaultErrorCorrection: ErrorCorrectionLevel
  defaultSize: number
  // Phase 2: Default shape settings
  defaultCornerShape?: CornerShape
  defaultDotShape?: DotShape
}
