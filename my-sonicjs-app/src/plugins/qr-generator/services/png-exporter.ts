/**
 * PNG Exporter Service
 * Converts SVG QR codes to PNG using @cf-wasm/resvg (WASM)
 *
 * This library is specifically designed for Cloudflare Workers edge runtime
 * where Canvas API is not available.
 *
 * DPI Options:
 * - 72 DPI: Web/screen display (default browser resolution)
 * - 150 DPI: Standard print quality
 * - 300 DPI: High-quality print (recommended for professional printing)
 */

// Import the Cloudflare Workers-compatible version
import { Resvg } from '@cf-wasm/resvg'

export type DpiOption = 72 | 150 | 300

export interface PngExportOptions {
  /** DPI for output image (72, 150, or 300) */
  dpi?: DpiOption
  /** Base size of QR code in pixels at 72 DPI */
  baseSize?: number
  /** Enable transparent background */
  transparent?: boolean
}

export interface PngExportResult {
  /** PNG image as Uint8Array */
  buffer: Uint8Array
  /** Width of output image in pixels */
  width: number
  /** Height of output image in pixels */
  height: number
  /** Actual file size in bytes */
  size: number
  /** Content type for HTTP response */
  contentType: 'image/png'
}

export class PngExporter {
  /**
   * Convert SVG to PNG with specified DPI
   *
   * @param svgString - The SVG string to convert
   * @param options - Export options including DPI
   * @returns PNG buffer and metadata
   */
  async export(svgString: string, options: PngExportOptions = {}): Promise<PngExportResult> {
    const {
      dpi = 300,
      baseSize = 300,
      transparent = false
    } = options

    // Calculate output dimensions based on DPI
    // At 72 DPI, 1 CSS pixel = 1 device pixel
    // At 300 DPI, we scale up by 300/72 = ~4.17x
    const scale = dpi / 72
    const outputSize = Math.round(baseSize * scale)

    // Modify SVG for transparent background if requested
    let processedSvg = svgString
    if (transparent) {
      processedSvg = this.makeTransparent(svgString)
    }

    try {
      // Initialize resvg with the SVG string
      const resvg = new Resvg(processedSvg, {
        fitTo: {
          mode: 'width',
          value: outputSize
        }
      })

      // Render to PNG
      const pngData = resvg.render()
      const pngBuffer = pngData.asPng()

      return {
        buffer: pngBuffer,
        width: pngData.width,
        height: pngData.height,
        size: pngBuffer.length,
        contentType: 'image/png'
      }
    } catch (error) {
      console.error('[PngExporter] Error converting SVG to PNG:', error)
      throw new Error(`PNG export failed: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  /**
   * Make SVG background transparent
   * Removes or modifies background rect to have no fill
   */
  private makeTransparent(svgString: string): string {
    // The qrcode-svg library creates a background rect with the background color
    // We need to either remove it or make it transparent

    // Pattern: Match rect elements that are background rectangles
    // qrcode-svg uses percentage width/height ("100%") or pixel values matching full size
    // We look for the first rect which is typically the background

    // Approach 1: Replace fill on rect with width="100%" or height="100%"
    let result = svgString.replace(
      /(<rect[^>]*width="100%"[^>]*fill=")[^"]*(")/,
      '$1none$2'
    ).replace(
      /(<rect[^>]*height="100%"[^>]*width="100%"[^>]*fill=")[^"]*(")/,
      '$1none$2'
    )

    // Approach 2: Handle pixel-based dimensions (e.g., width="300" height="300")
    // The background rect is typically the first rect with full dimensions
    // We detect this by looking for rect with x="0" y="0" and matching svg dimensions
    if (result === svgString) {
      // If no 100% patterns matched, try to find the first background rect
      // This handles cases where qrcode-svg uses pixel values
      result = svgString.replace(
        /(<rect\s+(?:x="0"\s+)?(?:y="0"\s+)?[^>]*fill=")([^"]+)("[^>]*>)/,
        (match, prefix, fill, suffix) => {
          // Only replace if this looks like a background (white or light color)
          if (fill.match(/^#(?:fff|ffffff|FFFFFF)$/i) || fill === 'white') {
            return `${prefix}none${suffix}`
          }
          return match
        }
      )
    }

    return result
  }

  /**
   * Estimate PNG file size before generating
   * Useful for warning users about large files
   *
   * @param baseSize - Base size in pixels
   * @param dpi - Target DPI
   * @returns Estimated size in bytes
   */
  static estimateSize(baseSize: number, dpi: DpiOption): number {
    const scale = dpi / 72
    const outputSize = Math.round(baseSize * scale)

    // PNG size estimation:
    // - Raw pixel data: width * height * 4 bytes (RGBA)
    // - PNG compression typically achieves 10-30% of raw size for simple graphics
    // - QR codes compress very well (black/white only)
    const rawSize = outputSize * outputSize * 4
    const compressionRatio = 0.15 // 15% of raw size (conservative estimate for QR codes)

    return Math.round(rawSize * compressionRatio)
  }

  /**
   * Check if estimated size exceeds soft limit
   * Returns warning message if size is concerning
   */
  static checkSizeWarning(baseSize: number, dpi: DpiOption): string | null {
    const estimatedBytes = PngExporter.estimateSize(baseSize, dpi)
    const estimatedMB = estimatedBytes / (1024 * 1024)

    // Soft limit: 5MB (from CONTEXT.md)
    if (estimatedMB > 5) {
      return `Estimated PNG size is ${estimatedMB.toFixed(1)}MB. Large files may take longer to generate and download.`
    }

    return null
  }

  /**
   * Get recommended DPI based on use case
   */
  static getRecommendedDpi(useCase: 'web' | 'screen' | 'print'): DpiOption {
    switch (useCase) {
      case 'web':
        return 72
      case 'screen':
        return 150
      case 'print':
        return 300
      default:
        return 300
    }
  }
}

/**
 * Convenience function for simple PNG export
 */
export async function exportPng(
  svgString: string,
  dpi: DpiOption = 300,
  transparent: boolean = false
): Promise<Uint8Array> {
  const exporter = new PngExporter()
  const result = await exporter.export(svgString, { dpi, transparent })
  return result.buffer
}

export const pngExporter = new PngExporter()
