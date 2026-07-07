import { describe, it, expect } from 'vitest'
import { getBlocksFieldConfig, parseBlocksValue } from '../../utils/blocks'

describe('blocks utils', () => {
  it('returns null when no blocks config is present', () => {
    expect(getBlocksFieldConfig(undefined)).toBeNull()
    expect(getBlocksFieldConfig({})).toBeNull()
    expect(getBlocksFieldConfig({ items: {} })).toBeNull()
  })

  it('returns blocks config with default discriminator', () => {
    const config = getBlocksFieldConfig({
      items: {
        blocks: {
          text: { properties: { heading: { type: 'string' } } }
        }
      }
    })

    expect(config).toEqual({
      blocks: {
        text: { properties: { heading: { type: 'string' } } }
      },
      discriminator: 'blockType'
    })
  })

  it('parses blocks JSON with discriminator key and assigns stable blockId', () => {
    const config = {
      blocks: {
        text: { properties: { heading: { type: 'string' } } }
      },
      discriminator: 'blockType'
    }
    const input = JSON.stringify([
      { blockType: 'text', heading: 'Hello' }
    ])

    const parsed = parseBlocksValue(input, config)

    expect(parsed.errors).toEqual([])
    expect(parsed.value).toHaveLength(1)
    expect(parsed.value[0].blockType).toBe('text')
    expect(parsed.value[0].heading).toBe('Hello')
    expect(parsed.value[0].blockId).toMatch(/^blk_[0-9a-f]{12}$/)
  })

  it('preserves existing blockId on re-parse (reorder/edit)', () => {
    const config = {
      blocks: {
        text: { properties: { heading: { type: 'string' } } }
      },
      discriminator: 'blockType'
    }
    const existingId = 'blk_aabbccddeeff'
    const input = JSON.stringify([
      { blockId: existingId, blockType: 'text', heading: 'Hello' }
    ])

    const parsed = parseBlocksValue(input, config)

    expect(parsed.errors).toEqual([])
    expect(parsed.value[0].blockId).toBe(existingId)
  })

  it('converts legacy blockType/data shape and assigns blockId', () => {
    const config = {
      blocks: {
        text: { properties: { heading: { type: 'string' } } }
      },
      discriminator: 'blockType'
    }
    const input = JSON.stringify([
      { blockType: 'text', data: { heading: 'Hello' } }
    ])

    const parsed = parseBlocksValue(input, config)

    expect(parsed.errors).toEqual([])
    expect(parsed.value[0].blockType).toBe('text')
    expect(parsed.value[0].heading).toBe('Hello')
    expect(parsed.value[0].blockId).toMatch(/^blk_[0-9a-f]{12}$/)
  })

  it('reports errors for invalid JSON and missing discriminator', () => {
    const config = {
      blocks: {
        text: { properties: { heading: { type: 'string' } } }
      },
      discriminator: 'blockType'
    }

    const invalidJson = parseBlocksValue('{invalid}', config)
    expect(invalidJson.errors).toEqual(['Blocks value must be valid JSON'])

    const missingDiscriminator = parseBlocksValue([{ heading: 'Hello' }], config)
    expect(missingDiscriminator.errors).toEqual(['Block #1 is missing "blockType"'])
  })
})
