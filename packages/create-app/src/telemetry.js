/**
 * Telemetry for create-sonicjs CLI
 *
 * Privacy-first telemetry to track installation metrics
 * - Anonymous installation IDs
 * - No PII collection
 * - Opt-out via environment variable
 */

import { randomUUID } from 'node:crypto'
import os from 'os'
import fs from 'fs-extra'
import path from 'path'

const TELEMETRY_ENABLED = process.env.SONICJS_TELEMETRY !== 'false' && process.env.DO_NOT_TRACK !== '1'
const TELEMETRY_ENDPOINT = process.env.SONICJS_TELEMETRY_ENDPOINT || 'https://stats.sonicjs.com'
const DEBUG = process.env.DEBUG === 'true'

/**
 * Get or create installation ID
 */
function getInstallationId() {
  const telemetryDir = path.join(os.homedir(), '.sonicjs')
  const telemetryFile = path.join(telemetryDir, 'telemetry.json')

  try {
    // Try to read existing ID
    if (fs.existsSync(telemetryFile)) {
      const data = fs.readJsonSync(telemetryFile)
      if (data.installationId) {
        return data.installationId
      }
    }

    // Create new ID
    const installationId = randomUUID()
    fs.ensureDirSync(telemetryDir)
    fs.writeJsonSync(telemetryFile, { installationId, createdAt: new Date().toISOString() })

    return installationId
  } catch (error) {
    // If we can't read/write the file, generate a temporary ID
    if (DEBUG) {
      console.error('[Telemetry] Failed to get/create installation ID:', error)
    }
    return randomUUID()
  }
}

/**
 * Initialize telemetry
 */
let installationId = null

async function initTelemetry() {
  if (!TELEMETRY_ENABLED) {
    if (DEBUG) {
      console.log('[Telemetry] Disabled via environment variable')
    }
    return null
  }

  try {
    installationId = getInstallationId()

    if (DEBUG) {
      console.log('[Telemetry] Initialized with ID:', installationId)
    }

    return { installationId }
  } catch (error) {
    if (DEBUG) {
      console.error('[Telemetry] Initialization failed:', error)
    }
    return null
  }
}

const pendingRequests = []

/**
 * Track an event using custom SonicJS stats endpoint
 */
async function track(event, properties = {}) {
  if (!TELEMETRY_ENABLED) return

  try {
    if (!installationId) {
      await initTelemetry()
    }

    if (!installationId) return

    const timestamp = new Date().toISOString()

    // Use standard SonicJS collection API
    const payload = {
      data: {
        installation_id: installationId,
        event_type: event,
        properties: {
          ...properties,
          os: os.platform(),
          nodeVersion: process.version.split('.').slice(0, 2).join('.'), // e.g., "v18.0"
        },
        timestamp
      }
    }

    const req = fetch(`${TELEMETRY_ENDPOINT}/v1/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    }).catch(() => {})

    pendingRequests.push(req)

    if (DEBUG) {
      console.log('[Telemetry] Tracked:', event, payload)
    }
  } catch (error) {
    // Silent fail - telemetry should never break the CLI
    if (DEBUG) {
      console.error('[Telemetry] Failed to track event:', error)
    }
  }
}

/**
 * Shutdown telemetry — flush pending requests (max 3s wait)
 */
async function shutdown() {
  if (pendingRequests.length === 0) return
  const timeout = new Promise(resolve => setTimeout(resolve, 3000))
  await Promise.race([Promise.all(pendingRequests), timeout])
}

/**
 * Check if telemetry is enabled
 */
function isEnabled() {
  return TELEMETRY_ENABLED
}

export {
  initTelemetry,
  track,
  shutdown,
  isEnabled,
  getInstallationId
}
