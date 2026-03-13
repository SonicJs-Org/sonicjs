import { describe, expect, it } from 'vitest'
import { getMDXEditorInitScript } from '../../plugins/available/easy-mdx'
import { getTinyMCEInitScript } from '../../plugins/available/tinymce-plugin'

describe('editor init scripts', () => {
  it('scopes TinyMCE initialization to tinymce provider containers', () => {
    const script = getTinyMCEInitScript()

    expect(script).toContain('.richtext-container[data-editor-provider="tinymce"] textarea')
    expect(script).not.toContain("document.querySelectorAll('.richtext-container textarea')")
  })

  it('scopes EasyMDE initialization to easymde provider containers', () => {
    const script = getMDXEditorInitScript()

    expect(script).toContain('.richtext-container[data-editor-provider="easymde"] textarea')
    expect(script).not.toContain("document.querySelectorAll('.richtext-container textarea')")
  })
})
