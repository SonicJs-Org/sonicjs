// Regex: matches #RGB or #RRGGBB (case-insensitive)
const HEX_COLOR_REGEX = /^#([a-fA-F0-9]{6}|[a-fA-F0-9]{3})$/

export function isValidHexColor(color: string): boolean {
  return HEX_COLOR_REGEX.test(color?.trim() ?? '')
}

export function normalizeHexColor(color: string): string | null {
  const trimmed = (color ?? '').trim()

  if (!HEX_COLOR_REGEX.test(trimmed)) {
    return null  // Invalid, cannot normalize
  }

  // Expand shorthand (#fff -> #ffffff)
  if (trimmed.length === 4) {
    return '#' + trimmed[1] + trimmed[1] +
                 trimmed[2] + trimmed[2] +
                 trimmed[3] + trimmed[3]
  }

  return trimmed.toLowerCase()
}
