import application from '../../my-sonicjs-app/src/index'
import { previewFetch } from './utils/preview-handler'
import type { PreviewEnvironment } from './utils/preview-handler'

// Real SonicJS fetch/scheduled handlers, with only keyed test-environment diagnostics/cleanup.
export default {
  ...application,
  fetch(request: Request, env: PreviewEnvironment, context: ExecutionContext) {
    return previewFetch(request, env, async () => application.fetch(request, env as never, context))
  },
}
