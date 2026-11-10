// Test-only unexpected upstream error. Production never imports this fixture.
globalThis.fetch = async () => { throw new Error(process.env.PUBLISH_UNTRUSTED_ERROR); };
