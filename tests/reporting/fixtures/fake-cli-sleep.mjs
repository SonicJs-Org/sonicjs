// Fake CLI: sleeps long enough to trigger a timeout in tests.
// Uses an active timer to keep the event loop alive (required for SIGTERM to work correctly
// in Node v22 — `await new Promise(() => {})` without handles exits with code 13 immediately).
await new Promise(r => setTimeout(r, 300_000))
