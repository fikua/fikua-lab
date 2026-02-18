#!/bin/bash
# =============================================================================
# Fikua Lab — Build and push Docker image to DockerHub
# =============================================================================
# Reads version from gradle.properties and pushes with version tag + latest.
#
# Usage: ./deployment/envs/dev/release-docker.sh
# =============================================================================

set -euo pipefail

cd "$(dirname "$0")/../../.."

# Docker configuration
DOCKER_REGISTRY="oriolcanades"
DOCKER_IMAGE="fikua-lab"
GRADLE_VERSION=$(grep '^version=' suite/backend/gradle.properties | cut -d= -f2)
DOCKER_TAG="${FIKUA_VERSION:-${GRADLE_VERSION}}"
FULL_IMAGE="${DOCKER_REGISTRY}/${DOCKER_IMAGE}:${DOCKER_TAG}"
LATEST_IMAGE="${DOCKER_REGISTRY}/${DOCKER_IMAGE}:latest"

# Load DockerHub PAT from dev .env if available
DEV_ENV="deployment/envs/dev/.env"
if [ -f "$DEV_ENV" ]; then
    DOCKER_PAT=$(grep '^DOCKER_PAT=' "$DEV_ENV" | cut -d= -f2 | tr -d '"')
fi

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()    { echo -e "${CYAN}[STEP]${NC} $1"; }

# Build
log_step "Building Docker image: ${FULL_IMAGE}"
docker build -t "${FULL_IMAGE}" -t "${LATEST_IMAGE}" -f deployment/docker/Dockerfile .
log_success "Image built: ${FULL_IMAGE} + ${LATEST_IMAGE}"

# Push
log_step "Pushing to DockerHub: ${FULL_IMAGE} + latest"
if [ -n "${DOCKER_PAT:-}" ]; then
    echo "${DOCKER_PAT}" | docker login -u "${DOCKER_REGISTRY}" --password-stdin
fi
docker push "${FULL_IMAGE}"
docker push "${LATEST_IMAGE}"
log_success "Image pushed: ${FULL_IMAGE} + ${LATEST_IMAGE}"
