// Error correction levels per ISO 18004
export type ErrorCorrectionLevel = 'L' | 'M' | 'Q' | 'H'

// Shape types for corners (eye patterns / position detection patterns)
export type CornerShape = 'square' | 'rounded' | 'dots' | 'extra-rounded'

// Shape types for data modules (dots)
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
  cornerShape: CornerShape | null  // Shape for eye patterns
  dotShape: DotShape | null  // Shape for data modules
  eyeColor: string | null  // Hex color for position detection patterns
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
  cornerShape?: CornerShape  // Default: square
  dotShape?: DotShape  // Default: square
  eyeColor?: string  // Default: same as foregroundColor
}

// Input for updating existing QR code
export interface UpdateQRCodeInput {
  name?: string | null
  destinationUrl?: string
  foregroundColor?: string
  backgroundColor?: string
  errorCorrection?: ErrorCorrectionLevel
  size?: number
  cornerShape?: CornerShape | null
  dotShape?: DotShape | null
  eyeColor?: string | null
}

// Options for generating QR code image
export interface QRCodeGenerateOptions {
  content: string
  size?: number
  foregroundColor?: string
  backgroundColor?: string
  errorCorrection?: ErrorCorrectionLevel
  format?: 'svg' | 'dataUrl'
  cornerShape?: CornerShape
  dotShape?: DotShape
  eyeColor?: string
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
  defaultCornerShape: CornerShape
  defaultDotShape: DotShape
}
