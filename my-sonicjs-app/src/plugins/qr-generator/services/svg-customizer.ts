/**
 * SVG Customizer Service
 *
 * Post-processes qrcode-svg output to apply custom shapes and eye colors.
 * Uses linkedom for DOM-like SVG manipulation without browser APIs.
 */

import { parseHTML } from 'linkedom'
import {
  type CornerShape,
  type DotShape,
  getCornerPathGenerator,
  getDotPathGenerator,
  type ShapeConfig
} from '../utils/svg-shapes'

/**
 * Options for SVG customization
 */
export interface SvgCustomizerOptions {
  cornerShape?: CornerShape
  dotShape?: DotShape
  eyeColor?: string  // Hex color for position detection patterns (eyes)
  moduleColor?: string  // Hex color for data modules (default foreground)
}

/**
 * QR code matrix position info
 */
interface ModulePosition {
  row: number
  col: number
  x: number
  y: number
  size: number
}

/**
 * Parse rect element attributes into module position
 */
function parseRectElement(rect: Element): ModulePosition | null {
  const x = parseFloat(rect.getAttribute('x') ?? '0')
  const y = parseFloat(rect.getAttribute('y') ?? '0')
  const width = parseFloat(rect.getAttribute('width') ?? '0')
  const height = parseFloat(rect.getAttribute('height') ?? '0')

  // Skip if not a valid module (rects should be square)
  if (width <= 0 || Math.abs(width - height) > 0.001) {
    return null
  }

  return {
    row: 0,  // Will be calculated
    col: 0,  // Will be calculated
    x,
    y,
    size: width
  }
}

/**
 * Check if a module position is within one of the three eye regions
 *
 * Eye regions are 7x7 modules at three corners of the QR code.
 * The quiet zone is 4 modules, so we need to account for that offset.
 *
 * Position detection patterns are at:
 * - Top-left: (0,0) to (6,6)
 * - Top-right: (0, modules-7) to (6, modules-1)
 * - Bottom-left: (modules-7, 0) to (modules-1, 6)
 */
export function isInEyeRegion(
  row: number,
  col: number,
  matrixSize: number
): boolean {
  // Eye patterns are 7x7 modules
  const eyeSize = 7

  // Top-left eye
  if (row < eyeSize && col < eyeSize) {
    return true
  }

  // Top-right eye
  if (row < eyeSize && col >= matrixSize - eyeSize) {
    return true
  }

  // Bottom-left eye
  if (row >= matrixSize - eyeSize && col < eyeSize) {
    return true
  }

  return false
}

/**
 * Calculate the QR matrix position from SVG coordinates
 *
 * qrcode-svg adds a 4-module quiet zone around the QR code.
 * We need to account for this when determining row/col.
 */
function calculateMatrixPosition(
  x: number,
  y: number,
  moduleSize: number,
  quietZone: number
): { row: number; col: number } {
  // Subtract quiet zone offset to get actual matrix position
  const adjustedX = x - (quietZone * moduleSize)
  const adjustedY = y - (quietZone * moduleSize)

  return {
    col: Math.round(adjustedX / moduleSize),
    row: Math.round(adjustedY / moduleSize)
  }
}

/**
 * Estimate matrix size from SVG dimensions and module size
 *
 * The SVG includes quiet zone (4 modules on each side).
 * Total SVG size = (matrixSize + 2 * quietZone) * moduleSize
 */
function estimateMatrixSize(
  svgWidth: number,
  moduleSize: number,
  quietZone: number
): number {
  const totalModules = Math.round(svgWidth / moduleSize)
  return totalModules - (2 * quietZone)
}

/**
 * SVG Customizer class for post-processing QR code SVGs
 */
export class SvgCustomizer {
  private readonly quietZone = 4  // ISO 18004 standard quiet zone

  /**
   * Customize an SVG string with custom shapes and eye colors
   *
   * @param svgString - The original SVG from qrcode-svg (generated with join:false)
   * @param options - Customization options
   * @returns Customized SVG string
   */
  customize(svgString: string, options: SvgCustomizerOptions): string {
    // If no customization needed, return as-is
    if (!options.cornerShape && !options.dotShape && !options.eyeColor) {
      return svgString
    }

    // Parse SVG using linkedom
    const { document } = parseHTML(svgString)
    const svg = document.querySelector('svg')

    if (!svg) {
      return svgString
    }

    // Get all rect elements (modules) - convert NodeList to array for iteration
    const rectsNodeList = svg.querySelectorAll('rect')
    const rects = Array.from(rectsNodeList) as Element[]
    if (rects.length === 0) {
      return svgString
    }

    // Find module size from first valid rect (skip background rect if present)
    let moduleSize = 0
    let firstModuleRect: Element | null = null

    for (const rect of rects) {
      const width = parseFloat(rect.getAttribute('width') ?? '0')
      const height = parseFloat(rect.getAttribute('height') ?? '0')

      // Skip background rect (usually full size) and non-square rects
      if (width > 0 && Math.abs(width - height) < 0.001 && width < 50) {
        moduleSize = width
        firstModuleRect = rect
        break
      }
    }

    if (moduleSize === 0 || !firstModuleRect) {
      return svgString
    }

    // Get SVG dimensions
    const svgWidth = parseFloat(svg.getAttribute('width') ?? '0')
    if (svgWidth === 0) {
      return svgString
    }

    // Calculate matrix size
    const matrixSize = estimateMatrixSize(svgWidth, moduleSize, this.quietZone)

    // Get path generators
    const cornerGenerator = options.cornerShape
      ? getCornerPathGenerator(options.cornerShape)
      : null
    const dotGenerator = options.dotShape
      ? getDotPathGenerator(options.dotShape)
      : null

    // Default colors from options or preserve original
    const eyeColor = options.eyeColor
    const moduleColor = options.moduleColor

    // Create path elements to replace rects
    const pathsToAdd: string[] = []
    const rectsToRemove: Element[] = []

    for (const rect of rects) {
      const pos = parseRectElement(rect)
      if (!pos) continue

      // Calculate matrix position accounting for quiet zone
      const { row, col } = calculateMatrixPosition(
        pos.x,
        pos.y,
        moduleSize,
        this.quietZone
      )

      // Skip rects that are outside the matrix (part of quiet zone or background)
      if (row < 0 || col < 0 || row >= matrixSize || col >= matrixSize) {
        continue
      }

      const isEye = isInEyeRegion(row, col, matrixSize)
      const generator = isEye ? cornerGenerator : dotGenerator
      const color = isEye && eyeColor
        ? eyeColor
        : (rect.getAttribute('fill') ?? moduleColor ?? '#000000')

      // If we have a custom generator, replace with path
      if (generator) {
        const config: ShapeConfig = {
          x: pos.x,
          y: pos.y,
          size: pos.size
        }
        const pathData = generator(config)
        pathsToAdd.push(`<path d="${pathData}" fill="${color}"/>`)
        rectsToRemove.push(rect)
      } else if (isEye && eyeColor) {
        // No shape change, but need to update eye color
        rect.setAttribute('fill', eyeColor)
      }
    }

    // Remove old rects and add new paths
    for (const rect of rectsToRemove) {
      rect.remove()
    }

    if (pathsToAdd.length > 0) {
      // Insert paths as innerHTML
      const existingContent = svg.innerHTML
      svg.innerHTML = existingContent + pathsToAdd.join('')
    }

    // Return the modified SVG
    return svg.outerHTML
  }

  /**
   * Generate a customized QR code SVG
   *
   * This is a convenience method that combines qrcode-svg generation
   * with customization in one step.
   *
   * @param qrcodeSvgInstance - An instance of qrcode-svg (already configured)
   * @param options - Customization options
   * @returns Customized SVG string
   */
  generateCustomizedSvg(
    qrcodeSvgInstance: { svg: () => string },
    options: SvgCustomizerOptions
  ): string {
    const svgString = qrcodeSvgInstance.svg()
    return this.customize(svgString, options)
  }
}

/**
 * Singleton instance for convenience
 */
export const svgCustomizer = new SvgCustomizer()
