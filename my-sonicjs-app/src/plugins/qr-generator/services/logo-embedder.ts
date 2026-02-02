/**
 * Logo Embedder Service
 * Embeds logos into QR code SVGs using SVG composition
 *
 * Logo embedding constraints:
 * - Maximum logo coverage: 5% of QR code area (~22% linear width)
 * - This ensures logo fits within the center data area (between eyes)
 * - White padding behind logo for visibility
 * - Logo container matches uploaded logo's aspect ratio
 * - Requires Level H error correction (30% capacity)
 */

import { parseHTML } from 'linkedom'

export interface LogoEmbedOptions {
  /** Data URL of the logo (PNG or SVG as base64) */
  logoDataUrl: string
  /** Aspect ratio of the logo (width / height) */
  logoAspectRatio: number
  /** Padding percentage around logo (0.1 = 10%) */
  paddingPercent?: number
  /** Maximum coverage of QR code area (0.05 = 5% area = ~22% linear width) */
  maxCoverage?: number
}

export class LogoEmbedder {
  /**
   * Embed a logo into the center of a QR code SVG
   *
   * Algorithm:
   * 1. Calculate maximum logo dimensions (sqrt of coverage for area)
   * 2. Apply aspect ratio to get actual width/height
   * 3. Add padding for white background
   * 4. Center position the logo container
   * 5. Add white background rect + logo image element
   */
  embed(svgString: string, options: LogoEmbedOptions): string {
    const {
      logoDataUrl,
      logoAspectRatio,
      paddingPercent = 0.15,
      maxCoverage = 0.05  // 5% area = ~22% linear width, fits safely in center data area
    } = options

    if (!logoDataUrl) {
      return svgString
    }

    const { document } = parseHTML(svgString)
    const svg = document.querySelector('svg')

    if (!svg) {
      console.warn('[LogoEmbedder] No SVG element found')
      return svgString
    }

    // Get SVG dimensions
    const svgWidth = parseInt(svg.getAttribute('width') || '300')
    const svgHeight = parseInt(svg.getAttribute('height') || '300')
    const svgSize = Math.min(svgWidth, svgHeight)

    // Calculate maximum logo dimensions
    // For 25% area coverage, the linear dimension is sqrt(0.25) = 0.5
    const maxLinearSize = svgSize * Math.sqrt(maxCoverage)

    // Apply aspect ratio to get actual dimensions
    let logoWidth: number
    let logoHeight: number

    if (logoAspectRatio >= 1) {
      // Landscape or square logo
      logoWidth = maxLinearSize
      logoHeight = maxLinearSize / logoAspectRatio
    } else {
      // Portrait logo
      logoHeight = maxLinearSize
      logoWidth = maxLinearSize * logoAspectRatio
    }

    // Calculate padding
    const paddingX = logoWidth * paddingPercent
    const paddingY = logoHeight * paddingPercent

    // Total container size including padding
    const containerWidth = logoWidth + (paddingX * 2)
    const containerHeight = logoHeight + (paddingY * 2)

    // Center position
    const containerX = (svgWidth - containerWidth) / 2
    const containerY = (svgHeight - containerHeight) / 2

    // Create white background rectangle
    const bgRect = document.createElementNS('http://www.w3.org/2000/svg', 'rect')
    bgRect.setAttribute('x', containerX.toString())
    bgRect.setAttribute('y', containerY.toString())
    bgRect.setAttribute('width', containerWidth.toString())
    bgRect.setAttribute('height', containerHeight.toString())
    bgRect.setAttribute('fill', '#FFFFFF')

    // Create logo image element
    const logoImage = document.createElementNS('http://www.w3.org/2000/svg', 'image')
    logoImage.setAttribute('x', (containerX + paddingX).toString())
    logoImage.setAttribute('y', (containerY + paddingY).toString())
    logoImage.setAttribute('width', logoWidth.toString())
    logoImage.setAttribute('height', logoHeight.toString())
    logoImage.setAttribute('href', logoDataUrl)
    // Preserve aspect ratio
    logoImage.setAttribute('preserveAspectRatio', 'xMidYMid meet')

    // Append to SVG (after QR modules so logo appears on top)
    svg.appendChild(bgRect)
    svg.appendChild(logoImage)

    return svg.toString()
  }

  /**
   * Calculate aspect ratio from image dimensions
   */
  static calculateAspectRatio(width: number, height: number): number {
    if (height === 0) return 1
    return width / height
  }

  /**
   * Validate logo data URL format
   */
  static isValidLogoDataUrl(dataUrl: string): boolean {
    if (!dataUrl) return false

    // Check for valid data URL format
    const validPrefixes = [
      'data:image/png;base64,',
      'data:image/svg+xml;base64,',
      'data:image/jpeg;base64,',
      'data:image/jpg;base64,'
    ]

    return validPrefixes.some(prefix => dataUrl.startsWith(prefix))
  }

  /**
   * Estimate logo file size from data URL
   * Returns size in bytes
   */
  static estimateLogoSize(dataUrl: string): number {
    if (!dataUrl) return 0

    // Extract base64 portion
    const base64 = dataUrl.split(',')[1]
    if (!base64) return 0

    // Base64 encoding increases size by ~33%
    return Math.round(base64.length * 0.75)
  }
}

// Convenience function for simple embedding
export function embedLogo(
  svgString: string,
  logoDataUrl: string,
  logoAspectRatio: number
): string {
  const embedder = new LogoEmbedder()
  return embedder.embed(svgString, { logoDataUrl, logoAspectRatio })
}

export const logoEmbedder = new LogoEmbedder()
