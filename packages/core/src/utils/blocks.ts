import type { BlockDefinitions } from '../types/collection-config'

export type BlocksFieldConfig = {
  blocks: BlockDefinitions
  discriminator: string
}

export function getBlocksFieldConfig(fieldOptions: any): BlocksFieldConfig | null {
  if (!fieldOptions || typeof fieldOptions !== 'object') return null

  const itemsConfig = fieldOptions.items && typeof fieldOptions.items === 'object'
    ? fieldOptions.items
    : null

  if (!itemsConfig || !itemsConfig.blocks || typeof itemsConfig.blocks !== 'object') {
    return null
  }

  const discriminator = typeof itemsConfig.discriminator === 'string' && itemsConfig.discriminator
    ? itemsConfig.discriminator
    : 'blockType'

  return {
    blocks: itemsConfig.blocks as BlockDefinitions,
    discriminator
  }
}

function generateBlockId(): string {
  const bytes = new Uint8Array(6)
  crypto.getRandomValues(bytes)
  return 'blk_' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

export function parseBlocksValue(value: unknown, config: BlocksFieldConfig) {
  const errors: string[] = []
  let rawValue = value

  if (rawValue === null || rawValue === undefined || rawValue === '') {
    return { value: [] as any[], errors }
  }

  if (typeof rawValue === 'string') {
    try {
      rawValue = JSON.parse(rawValue)
    } catch {
      return { value: [] as any[], errors: ['Blocks value must be valid JSON'] }
    }
  }

  if (!Array.isArray(rawValue)) {
    return { value: [] as any[], errors: ['Blocks value must be an array'] }
  }

  const normalized = rawValue.map((item, index) => {
    if (!item || typeof item !== 'object') {
      errors.push(`Block #${index + 1} must be an object`)
      return null
    }

    let block: any
    if ((item as any).blockType && (item as any).data && typeof (item as any).data === 'object') {
      block = { [config.discriminator]: (item as any).blockType, ...(item as any).data }
    } else {
      if (!(config.discriminator in (item as any))) {
        errors.push(`Block #${index + 1} is missing "${config.discriminator}"`)
      }
      block = item as any
    }

    // Preserve existing blockId or generate a stable one for new blocks
    if (!block.blockId) {
      block = { blockId: generateBlockId(), ...block }
    }

    return block
  }).filter((item) => item !== null)

  return { value: normalized, errors }
}
