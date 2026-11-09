// Fake CLI: emits >64KB to stdout to trigger overflow
const chunk = 'x'.repeat(1024)
for (let i = 0; i < 80; i++) process.stdout.write(chunk) // 80KB
