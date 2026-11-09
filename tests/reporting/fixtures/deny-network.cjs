// Loaded in the CLI and inherited workers. Every outbound transport fails closed.
const fs = require('node:fs')
function deny() { throw new Error('REPORTING_NETWORK_DENIED') }
globalThis.fetch = deny
for (const name of ['node:http', 'node:https']) {
  const transport = require(name)
  transport.request = deny
  transport.get = deny
}
require('node:net').Socket.prototype.connect = deny
require('node:tls').connect = deny
