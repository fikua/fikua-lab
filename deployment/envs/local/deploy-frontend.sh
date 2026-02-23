#!/bin/bash
# =============================================================================
# Fikua Lab — Serve frontend locally
# =============================================================================
# Landing:     http://localhost:3000
# Portal:      http://localhost:3001
# Issuer:      http://localhost:3002
# Certificate: http://localhost:3003
# Wallet:      http://localhost:3004
# Verifier:    http://localhost:3005
# Identify:    http://localhost:3006
# =============================================================================

set -euo pipefail

cd "$(dirname "$0")/../../.."

cleanup() {
    echo ""
    echo "Stopping servers..."
    kill 0 2>/dev/null
}
trap cleanup EXIT

echo "Starting local frontend servers..."
echo "  Landing:     http://localhost:3000"
echo "  Portal:      http://localhost:3001"
echo "  Issuer:      http://localhost:3002"
echo "  Certificate: http://localhost:3003"
echo "  Wallet:      http://localhost:3004"
echo "  Verifier:    http://localhost:3005"
echo "  Identify:    http://localhost:3006"
echo ""
echo "Press Ctrl+C to stop"
echo ""

python3 -m http.server 3000 -d suite/frontend/landing &
python3 -m http.server 3001 -d suite/frontend/portal &
python3 -m http.server 3002 -d suite/frontend/issuer &
python3 -m http.server 3003 -d suite/frontend/cert &
python3 -m http.server 3004 -d suite/frontend/holder &
python3 -m http.server 3005 -d suite/frontend/verifier &
python3 -m http.server 3006 -d suite/frontend/identify &
wait
