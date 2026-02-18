#!/bin/bash
# =============================================================================
# Fikua Lab — Deploy nginx config + SSL to VPS
# =============================================================================
# Uploads nginx-lab.conf, requests Let's Encrypt certificates if needed,
# and reloads nginx.
#
# Usage: ./deployment/envs/dev/deploy-nginx.sh
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

# --- Upload nginx config ---
log_step "Uploading nginx config..."
scp ${SCP_OPTS} "deployment/envs/dev/nginx/nginx-lab.conf" "${VPS_USER}@${VPS_IP}:/tmp/lab-fikua.conf"

ssh ${SSH_OPTS} "${VPS_USER}@${VPS_IP}" "
    sudo mv /tmp/lab-fikua.conf /etc/nginx/conf.d/lab-fikua.conf
"
log_success "Nginx config uploaded"

# --- SSL certificates ---
log_step "Checking SSL certificates..."
ssh ${SSH_OPTS} "${VPS_USER}@${VPS_IP}" "
    if [ -d '/etc/letsencrypt/live/lab.fikua.com' ]; then
        echo 'Certificate already exists for lab.fikua.com'
        sudo certbot certificates -d lab.fikua.com
    else
        echo 'Requesting new certificate (multi-domain)...'
        sudo certbot certonly --nginx -d lab.fikua.com -d portal.lab.fikua.com -d issuer.lab.fikua.com -d cert.lab.fikua.com -d wallet.lab.fikua.com -d verifier.lab.fikua.com --non-interactive --agree-tos -m ocanades@outlook.com
    fi
"
log_success "SSL certificates ready"

# --- Test and reload ---
log_step "Testing and reloading nginx..."
ssh ${SSH_OPTS} "${VPS_USER}@${VPS_IP}" "
    sudo nginx -t && sudo systemctl reload nginx
"
log_success "Nginx reloaded"

echo ""
log_success "Nginx deployed for *.lab.fikua.com (landing, portal, issuer, cert, wallet, verifier)"
