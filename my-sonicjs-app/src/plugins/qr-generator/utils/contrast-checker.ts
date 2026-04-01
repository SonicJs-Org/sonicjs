// WCAG 2.0 luminance calculation (sRGB)
function getLuminance(hex: string): number {
  // Remove # and parse RGB
  const r = parseInt(hex.slice(1, 3), 16) / 255
  const g = parseInt(hex.slice(3, 5), 16) / 255
  const b = parseInt(hex.slice(5, 7), 16) / 255

  // Apply gamma correction (sRGB to linear)
  const toLinear = (c: number) =>
    c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4)

  // Weighted sum per WCAG
  return 0.2126 * toLinear(r) + 0.7152 * toLinear(g) + 0.0722 * toLinear(b)
}

export function getContrastRatio(foreground: string, background: string): number {
  const l1 = getLuminance(foreground)
  const l2 = getLuminance(background)
  const lighter = Math.max(l1, l2)
  const darker = Math.min(l1, l2)
  return (lighter + 0.05) / (darker + 0.05)
}

// QR codes need at least 3:1 contrast for reliable scanning
const MIN_CONTRAST_RATIO = 3.0

export function isLowContrast(foreground: string, background: string): boolean {
  return getContrastRatio(foreground, background) < MIN_CONTRAST_RATIO
}

export function getContrastWarning(foreground: string, background: string): string | null {
  const ratio = getContrastRatio(foreground, background)
  if (ratio < MIN_CONTRAST_RATIO) {
    return `Low contrast (${ratio.toFixed(1)}:1). QR code may be difficult to scan. Recommended: 3:1 minimum.`
  }
  return null
}
