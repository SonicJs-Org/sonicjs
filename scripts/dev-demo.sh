#!/usr/bin/env bash
set -e

BACKEND_PORT=${BACKEND_PORT:-9876}
FRONTEND_PORT=5199

echo "▶ Backend:    http://localhost:$BACKEND_PORT"
echo "▶ React demo: http://localhost:$FRONTEND_PORT"
echo ""

# Start backend on fixed port
BACKEND_PORT=$BACKEND_PORT npm run dev:demo:react --workspace=my-sonicjs-app &
BACKEND_PID=$!

cleanup() {
  kill "$BACKEND_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Wait for backend to be ready before starting Vite
echo "Waiting for backend..."
until curl -s "http://localhost:$BACKEND_PORT/api/employees?limit=1&status=published" > /dev/null 2>&1; do
  sleep 2
done
echo "Backend ready."

# Vite proxies /api and /v1 to backend — no CORS, same origin for browser
cd demos/employee-directory
VITE_DEV_BACKEND="http://localhost:$BACKEND_PORT" \
  VITE_CMS_URL="http://localhost:$FRONTEND_PORT" \
  npm run dev
