import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { test } from 'vitest'

// Keep the existing verifier, output streams, working directory, and cleanup owner.
test('existing standalone CLI verifier', async () => {
  const child = spawn(process.execPath, ['test-cli.js'], {
    cwd: fileURLToPath(new URL('.', import.meta.url)), stdio: 'inherit',
  })
  const code = await new Promise<number | null>((resolve, reject) => {
    child.on('error', reject)
    child.on('close', (code, signal) => {
      if (signal) {
        process.kill(process.pid, signal)
        reject(new Error(`CLI verifier terminated: ${signal}`))
      } else resolve(code)
    })
  })
  if (code !== 0) throw new Error(`CLI verifier exited ${code}`)
})
