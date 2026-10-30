import { prepareEnvironment } from '../tests/e2e/global-setup'

if (!process.env.BASE_URL) throw new Error('Readiness requires the newly deployed preview BASE_URL')
await prepareEnvironment(process.env.BASE_URL)
