#!/bin/bash
# =============================================================================
# Fikua Lab — Deploy frontend to VPS
# =============================================================================
# Uploads all frontend apps to the VPS via SCP.
# Nginx serves them as static files.
#
# Usage: ./deployment/envs/dev/deploy-frontend.sh
# =============================================================================

set -euo pipefail

cd "$(dirname "$0")/../../.."

# VPS configuration
VPS_IP="51.38.179.236"
VPS_USER="ubuntu"
SSH_KEY="$(pwd)/deployment/envs/dev/ssh/id_ed25519"
SSH_PORT="49222"
SSH_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no -p ${SSH_PORT}"
SCP_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no -P ${SSH_PORT}"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()    { echo -e "${CYAN}[STEP]${NC} $1"; }

# Validate SSH key
if [ ! -f "$SSH_KEY" ]; then
    log_error "SSH key not found: $SSH_KEY"
    exit 1
fi

# Test VPS connection
log_info "Testing VPS connection..."
if ! ssh ${SSH_OPTS} "${VPS_USER}@${VPS_IP}" "echo 'ok'" > /dev/null 2>&1; then
    log_error "Cannot connect to VPS"
    exit 1
fi
log_success "VPS connection OK"

# --- Shared assets (error pages, consent banner) ---
if [ -d "suite/frontend/shared" ]; then
    log_step "Uploading shared assets..."
    ssh ${SSH_OPTS} "${VPS_USER}@${VPS_IP}" "sudo mkdir -p /opt/vps/frontends/lab/shared && sudo chown -R ubuntu:ubuntu /opt/vps/frontends/lab/shared"
    scp ${SCP_OPTS} -r "suite/frontend/shared/." "${VPS_USER}@${VPS_IP}:/opt/vps/frontends/lab/shared/"
    log_success "Shared assets uploaded"
fi

# --- Landing page → lab.fikua.com ---
if [ -d "suite/frontend/landing" ]; then
    log_step "Uploading landing page..."
    ssh ${SSH_OPTS} "${VPS_USER}@${VPS_IP}" "sudo mkdir -p /opt/vps/frontends/lab/landing && sudo chown -R ubuntu:ubuntu /opt/vps/frontends/lab/landing"
    scp ${SCP_OPTS} -r "suite/frontend/landing/." "${VPS_USER}@${VPS_IP}:/opt/vps/frontends/lab/landing/"
    log_success "Landing → https://lab.fikua.com"
fi

# --- Portal → portal.lab.fikua.com ---
if [ -d "suite/frontend/portal" ]; then
    log_step "Uploading portal..."
    ssh ${SSH_OPTS} "${VPS_USER}@${VPS_IP}" "sudo mkdir -p /opt/vps/frontends/lab/portal && sudo chown -R ubuntu:ubuntu /opt/vps/frontends/lab/portal"
    scp ${SCP_OPTS} -r "suite/frontend/portal/." "${VPS_USER}@${VPS_IP}:/opt/vps/frontends/lab/portal/"
    log_success "Portal → https://portal.lab.fikua.com"
fi

# --- Issuer → issuer.lab.fikua.com ---
if [ -d "suite/frontend/issuer" ]; then
    log_step "Uploading issuer..."
    ssh ${SSH_OPTS} "${VPS_USER}@${VPS_IP}" "sudo mkdir -p /opt/vps/frontends/lab/issuer && sudo chown -R ubuntu:ubuntu /opt/vps/frontends/lab/issuer"
    scp ${SCP_OPTS} -r "suite/frontend/issuer/." "${VPS_USER}@${VPS_IP}:/opt/vps/frontends/lab/issuer/"
    log_success "Issuer → https://issuer.lab.fikua.com"
fi

# --- Certificate → cert.lab.fikua.com ---
if [ -d "suite/frontend/cert" ]; then
    log_step "Uploading certificate..."
    ssh ${SSH_OPTS} "${VPS_USER}@${VPS_IP}" "sudo mkdir -p /opt/vps/frontends/lab/cert && sudo chown -R ubuntu:ubuntu /opt/vps/frontends/lab/cert"
    scp ${SCP_OPTS} -r "suite/frontend/cert/." "${VPS_USER}@${VPS_IP}:/opt/vps/frontends/lab/cert/"
    log_success "Certificate → https://cert.lab.fikua.com"
fi

# --- Wallet → wallet.lab.fikua.com ---
if [ -d "suite/frontend/holder" ]; then
    log_step "Uploading wallet..."
    ssh ${SSH_OPTS} "${VPS_USER}@${VPS_IP}" "sudo mkdir -p /opt/vps/frontends/lab/holder && sudo chown -R ubuntu:ubuntu /opt/vps/frontends/lab/holder"
    scp ${SCP_OPTS} -r "suite/frontend/holder/." "${VPS_USER}@${VPS_IP}:/opt/vps/frontends/lab/holder/"
    log_success "Wallet → https://wallet.lab.fikua.com"
fi

# --- Verifier → verifier.lab.fikua.com ---
if [ -d "suite/frontend/verifier" ]; then
    log_step "Uploading verifier..."
    ssh ${SSH_OPTS} "${VPS_USER}@${VPS_IP}" "sudo mkdir -p /opt/vps/frontends/lab/verifier && sudo chown -R ubuntu:ubuntu /opt/vps/frontends/lab/verifier"
    scp ${SCP_OPTS} -r "suite/frontend/verifier/." "${VPS_USER}@${VPS_IP}:/opt/vps/frontends/lab/verifier/"
    log_success "Verifier → https://verifier.lab.fikua.com"
fi

# --- Fix permissions ---
log_step "Setting permissions..."
ssh ${SSH_OPTS} "${VPS_USER}@${VPS_IP}" "
    sudo chown -R ubuntu:ubuntu /opt/vps/frontends/lab
    sudo find /opt/vps/frontends/lab -type d -exec chmod 755 {} \;
    sudo find /opt/vps/frontends/lab -type f -exec chmod 644 {} \;
"

log_success "All frontend deployed!"
