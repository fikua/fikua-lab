#!/bin/bash
# =============================================================================
# Fikua Lab — Backend Deployment Script (VPS)
# =============================================================================
# Usage: ./deployment/envs/dev/deploy-backend.sh <command>
#
# Commands:
#   deploy      - Deploy to VPS (pull image + restart)
#   cleanup     - Remove old Docker resources on VPS
#   full-deploy - cleanup + nginx + deploy
#   ssh         - SSH into VPS
#   logs        - Show backend logs on VPS
#   status      - Check backend health on VPS
#   reset       - Reset DB and restart on VPS
#   backup      - Download PostgreSQL backup to local
# =============================================================================

set -euo pipefail

# Change to project root
cd "$(dirname "$0")/../../.."

# VPS configuration
VPS_IP="51.38.179.236"
VPS_USER="ubuntu"
VPS_BASE_PATH="/opt/vps"
SSH_KEY="$(pwd)/deployment/envs/dev/ssh/id_ed25519"
SSH_PORT="49222"
SSH_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no -p ${SSH_PORT}"
SCP_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no -P ${SSH_PORT}"

# Docker configuration (for deploy command)
DOCKER_REGISTRY="oriolcanades"
DOCKER_IMAGE="fikua-lab"
GRADLE_VERSION=$(grep '^version=' suite/backend/gradle.properties | cut -d= -f2)
DOCKER_TAG="${FIKUA_VERSION:-${GRADLE_VERSION}}"
FULL_IMAGE="${DOCKER_REGISTRY}/${DOCKER_IMAGE}:${DOCKER_TAG}"

# Load DockerHub PAT from dev .env if available
DEV_ENV="deployment/envs/dev/.env"
if [ -f "$DEV_ENV" ]; then
    DOCKER_PAT=$(grep '^DOCKER_PAT=' "$DEV_ENV" | cut -d= -f2 | tr -d '"')
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()    { echo -e "${CYAN}[STEP]${NC} $1"; }

check_ssh_key() {
    if [ ! -f "$SSH_KEY" ]; then
        log_error "SSH key not found: $SSH_KEY"
        exit 1
    fi
}

check_vps() {
    check_ssh_key
    log_info "Testing VPS connection..."
    if ! ssh ${SSH_OPTS} "${VPS_USER}@${VPS_IP}" "echo 'ok'" > /dev/null 2>&1; then
        log_error "Cannot connect to VPS"
        exit 1
    fi
    log_success "VPS connection OK"
}

vps_exec() {
    ssh ${SSH_OPTS} "${VPS_USER}@${VPS_IP}" "$@"
}

vps_scp() {
    scp ${SCP_OPTS} "$@"
}

# =============================================================================
# Commands
# =============================================================================

cmd_cleanup() {
    check_vps
    log_step "Cleaning up old Docker resources on VPS..."

    vps_exec "
        cd /opt/vps/lab

        # Stop fikua-lab containers
        if [ -f 'compose.yaml' ]; then
            sudo docker compose --env-file .env -f compose.yaml down -v 2>/dev/null || true
        fi

        # Remove dangling images
        sudo docker image prune -af 2>/dev/null || true

        # Recreate directories
        sudo mkdir -p /opt/vps/frontends/lab
        sudo mkdir -p /opt/vps/lab
        sudo chown -R ubuntu:ubuntu /opt/vps/frontends/lab /opt/vps/lab

        echo 'Cleanup complete'
    "

    log_success "VPS cleaned up"
}

cmd_deploy() {
    check_vps
    log_step "Deploying fikua-lab to VPS..."

    # Upload compose.yaml
    vps_scp "deployment/envs/dev/docker/compose.yaml" "${VPS_USER}@${VPS_IP}:/opt/vps/lab/compose.yaml"

    vps_exec "
        cd /opt/vps/lab

        # Create .env if it doesn't exist
        if [ ! -f '.env' ]; then
            cat > .env << 'ENVEOF'
DOCKER_REGISTRY=oriolcanades
FIKUA_VERSION=${DOCKER_TAG}
FIKUA_POSTGRES_USER=fikua
FIKUA_POSTGRES_PASSWORD=fikua_lab_$(openssl rand -hex 8)
ENVEOF
            echo '.env created with random DB password'
        fi

        # Login to DockerHub
        echo '${DOCKER_PAT:-}' | sudo docker login -u '${DOCKER_REGISTRY}' --password-stdin 2>/dev/null || true

        # Pull and deploy
        echo 'Pulling image: ${FULL_IMAGE}...'
        sudo docker pull ${FULL_IMAGE}

        echo 'Starting services...'
        sudo docker compose --env-file .env -f compose.yaml up -d --force-recreate

        echo 'Waiting for health check...'
        sleep 15

        # Check health
        curl -sf http://localhost:8090/health && echo ' — Backend is UP' || echo ' — Backend not ready yet'

        echo ''
        sudo docker compose --env-file .env -f compose.yaml ps
    "

    log_success "Fikua Lab deployed!"
    log_info "Landing:     https://lab.fikua.com"
    log_info "Portal:      https://portal.lab.fikua.com"
    log_info "Issuer:      https://issuer.lab.fikua.com"
    log_info "Certificate: https://cert.lab.fikua.com"
    log_info "Wallet:      https://wallet.lab.fikua.com"
    log_info "Verifier:    https://verifier.lab.fikua.com"
}

cmd_ssh() {
    check_ssh_key
    ssh ${SSH_OPTS} "${VPS_USER}@${VPS_IP}"
}

cmd_logs() {
    check_vps
    vps_exec "cd /opt/vps/lab && sudo docker compose --env-file .env -f compose.yaml logs -f --tail=100 fikua-lab"
}

cmd_status() {
    check_vps
    log_info "Checking backend health..."
    HEALTH=$(vps_exec "curl -sf http://localhost:8090/health 2>/dev/null || echo '{\"status\":\"DOWN\"}'")
    echo "$HEALTH" | python3 -m json.tool 2>/dev/null || echo "$HEALTH"
}

cmd_reset() {
    check_vps
    log_warning "This will DELETE the database!"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]] || { log_info "Cancelled"; exit 0; }

    vps_exec "
        cd /opt/vps/lab
        sudo docker compose --env-file .env -f compose.yaml down -v
        sudo docker compose --env-file .env -f compose.yaml up -d
    "
    log_success "Database reset, services restarted"
}

cmd_backup() {
    check_vps
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_DIR="backups"
    BACKUP_FILE="fikua-lab-backup-${TIMESTAMP}.sql"

    mkdir -p "${BACKUP_DIR}"

    log_step "Backing up PostgreSQL to ${BACKUP_DIR}/${BACKUP_FILE}..."
    vps_exec "sudo docker exec fikua-lab-db pg_dump -U fikua fikua" > "${BACKUP_DIR}/${BACKUP_FILE}"

    if [ -s "${BACKUP_DIR}/${BACKUP_FILE}" ]; then
        log_success "Backup saved: ${BACKUP_DIR}/${BACKUP_FILE} ($(wc -c < "${BACKUP_DIR}/${BACKUP_FILE}" | tr -d ' ') bytes)"
    else
        rm -f "${BACKUP_DIR}/${BACKUP_FILE}"
        log_error "Backup failed — empty file"
        exit 1
    fi
}

cmd_full_deploy() {
    log_step "Full deployment: cleanup + nginx + deploy"
    echo ""
    cmd_cleanup
    echo ""
    log_step "Running deploy-nginx.sh..."
    chmod +x "$(dirname "$0")/deploy-nginx.sh"
    "$(dirname "$0")/deploy-nginx.sh"
    echo ""
    cmd_deploy
    echo ""
    log_success "Full deployment complete!"
}

# =============================================================================
# Main
# =============================================================================

show_usage() {
    echo "Usage: $0 <command>"
    echo ""
    echo "VPS Deployment:"
    echo "  deploy        Pull image and restart on VPS"
    echo "  cleanup       Remove old Docker resources on VPS"
    echo "  full-deploy   cleanup + nginx + deploy"
    echo ""
    echo "Operations:"
    echo "  ssh           SSH into VPS"
    echo "  logs          Show backend logs"
    echo "  status        Check health"
    echo "  reset         Reset DB and restart"
    echo "  backup        Download PostgreSQL backup to local"
}

if [ $# -lt 1 ]; then
    show_usage
    exit 1
fi

case "$1" in
    deploy)         cmd_deploy ;;
    cleanup)        cmd_cleanup ;;
    full-deploy)    cmd_full_deploy ;;
    ssh)            cmd_ssh ;;
    logs)           cmd_logs ;;
    status)         cmd_status ;;
    reset)          cmd_reset ;;
    backup)         cmd_backup ;;
    *)
        log_error "Unknown command: $1"
        show_usage
        exit 1
        ;;
esac
