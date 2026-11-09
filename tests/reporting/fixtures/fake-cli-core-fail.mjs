// A CLI can fail after contacting the service; its nonzero exit is not proof of no delivery.
if (process.argv.at(-1).includes('/core-unit/')) process.exit(1);
console.log('https://flakiness.io/r/cms-independent');
