/**
 * SVG path generators for custom QR code shapes
 *
 * Each shape generator creates an SVG path string for a single module (dot)
 * at the specified position with the specified size.
 */

// Shape types for corners (eye patterns)
export type CornerShape = 'square' | 'rounded' | 'dots' | 'extra-rounded'

// Shape types for data modules (dots)
export type DotShape = 'square' | 'rounded' | 'dots' | 'diamond'

/**
 * Configuration for shape generation
 */
export interface ShapeConfig {
  x: number      // Top-left X coordinate
  y: number      // Top-left Y coordinate
  size: number   // Module size
}

/**
 * Square path - default QR code module shape
 */
export function squarePath(config: ShapeConfig): string {
  const { x, y, size } = config
  return `M${x} ${y}h${size}v${size}h${-size}Z`
}

/**
 * Rounded path - square with rounded corners
 * Uses 30% of size for corner radius
 */
export function roundedPath(config: ShapeConfig): string {
  const { x, y, size } = config
  const radius = size * 0.3

  // Start at top-left + radius, go clockwise
  return [
    `M${x + radius} ${y}`,
    `h${size - 2 * radius}`,
    `a${radius} ${radius} 0 0 1 ${radius} ${radius}`,
    `v${size - 2 * radius}`,
    `a${radius} ${radius} 0 0 1 ${-radius} ${radius}`,
    `h${-(size - 2 * radius)}`,
    `a${radius} ${radius} 0 0 1 ${-radius} ${-radius}`,
    `v${-(size - 2 * radius)}`,
    `a${radius} ${radius} 0 0 1 ${radius} ${-radius}`,
    'Z'
  ].join('')
}

/**
 * Extra-rounded path - square with larger rounded corners
 * Uses 50% of size for corner radius (maximum rounding)
 */
export function extraRoundedPath(config: ShapeConfig): string {
  const { x, y, size } = config
  const radius = size * 0.5

  // With 50% radius, this becomes essentially a rounded rectangle
  // Start at top-left + radius, go clockwise
  return [
    `M${x + radius} ${y}`,
    `h${size - 2 * radius}`,
    `a${radius} ${radius} 0 0 1 ${radius} ${radius}`,
    `v${size - 2 * radius}`,
    `a${radius} ${radius} 0 0 1 ${-radius} ${radius}`,
    `h${-(size - 2 * radius)}`,
    `a${radius} ${radius} 0 0 1 ${-radius} ${-radius}`,
    `v${-(size - 2 * radius)}`,
    `a${radius} ${radius} 0 0 1 ${radius} ${-radius}`,
    'Z'
  ].join('')
}

/**
 * Circle path - circular module (dot style)
 */
export function circlePath(config: ShapeConfig): string {
  const { x, y, size } = config
  const radius = size / 2
  const cx = x + radius
  const cy = y + radius

  // SVG circle as path using two arcs
  return [
    `M${cx - radius} ${cy}`,
    `a${radius} ${radius} 0 1 0 ${size} 0`,
    `a${radius} ${radius} 0 1 0 ${-size} 0`,
    'Z'
  ].join('')
}

/**
 * Diamond path - 45-degree rotated square
 */
export function diamondPath(config: ShapeConfig): string {
  const { x, y, size } = config
  const half = size / 2
  const cx = x + half
  const cy = y + half

  // Diamond: start at top, go clockwise
  return [
    `M${cx} ${y}`,
    `l${half} ${half}`,
    `l${-half} ${half}`,
    `l${-half} ${-half}`,
    'Z'
  ].join('')
}

/**
 * Type for path generator functions
 */
export type PathGenerator = (config: ShapeConfig) => string

/**
 * Map of corner shape names to path generators
 */
export const cornerShapeGenerators: Record<CornerShape, PathGenerator> = {
  'square': squarePath,
  'rounded': roundedPath,
  'dots': circlePath,
  'extra-rounded': extraRoundedPath
}

/**
 * Map of dot shape names to path generators
 */
export const dotShapeGenerators: Record<DotShape, PathGenerator> = {
  'square': squarePath,
  'rounded': roundedPath,
  'dots': circlePath,
  'diamond': diamondPath
}

/**
 * Get path generator for corner shape
 */
export function getCornerPathGenerator(shape: CornerShape): PathGenerator {
  return cornerShapeGenerators[shape] ?? squarePath
}

/**
 * Get path generator for dot shape
 */
export function getDotPathGenerator(shape: DotShape): PathGenerator {
  return dotShapeGenerators[shape] ?? squarePath
}

/**
 * Unified helper to get any path generator by shape name
 * Useful when you know the shape type dynamically
 */
export function getPathGenerator(
  shape: CornerShape | DotShape,
  type: 'corner' | 'dot' = 'dot'
): PathGenerator {
  if (type === 'corner') {
    return getCornerPathGenerator(shape as CornerShape)
  }
  return getDotPathGenerator(shape as DotShape)
}
