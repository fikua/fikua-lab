# Fikua Lab — build and deployment shortcuts

.PHONY: help build run test clean compile local-up local-down local-logs local-frontend \
        docker-push deploy deploy-frontend deploy-nginx full-deploy \
        cleanup ssh logs status backup vps-reset reset pull push

.DEFAULT_GOAL := help

# =============================================================================
# Help
# =============================================================================

help: ## Show available commands
	@echo ""
	@echo "  Fikua Lab — available commands"
	@echo "  =============================="
	@echo ""
	@echo "  Development"
	@echo "  -----------"
	@echo "  make build            Build fat jar (Gradle)"
	@echo "  make run              Run backend locally (requires PostgreSQL)"
	@echo "  make compile          Quick compilation check"
	@echo "  make test             Run tests"
	@echo "  make clean            Clean build artifacts"
	@echo "  make reset            Reset test state (local POST /reset)"
	@echo ""
	@echo "  Local environment"
	@echo "  -----------------"
	@echo "  make local-up         Start backend + postgres (Docker Compose)"
	@echo "  make local-down       Stop local environment"
	@echo "  make local-logs       Tail backend logs (local)"
	@echo "  make local-frontend   Serve frontend locally (ports 3000-3005)"
	@echo ""
	@echo "  Docker"
	@echo "  ------"
	@echo "  make docker-push      Build + push image to DockerHub"
	@echo ""
	@echo "  VPS deploy"
	@echo "  ----------"
	@echo "  make deploy           Deploy backend to VPS (pull + restart)"
	@echo "  make deploy-frontend  Upload frontend to VPS (SCP)"
	@echo "  make deploy-nginx     Deploy nginx config + SSL to VPS"
	@echo "  make full-deploy      Cleanup + nginx + backend deploy"
	@echo "  make cleanup          Remove old Docker resources on VPS"
	@echo ""
	@echo "  VPS operations"
	@echo "  --------------"
	@echo "  make ssh              SSH into VPS"
	@echo "  make logs             Tail backend logs on VPS"
	@echo "  make status           Check VPS health"
	@echo "  make backup           Backup PostgreSQL from VPS"
	@echo "  make vps-reset        Reset VPS deployment (dangerous!)"
	@echo ""
	@echo "  Git sync"
	@echo "  --------"
	@echo "  make pull             Pull changes from remote"
	@echo "  make push             Commit and push all changes"
	@echo ""

# =============================================================================
# Backend development
# =============================================================================

# Build the fat jar
build:
	cd suite/backend && ./gradlew :fikua-server:fatJar

# Run locally (requires PostgreSQL running)
run: build
	cd suite/backend && java -jar fikua-server/build/libs/fikua-server-*-all.jar

# Compile only (quick check)
compile:
	cd suite/backend && ./gradlew compileJava

# Run tests
test:
	cd suite/backend && ./gradlew test

# Clean build artifacts
clean:
	cd suite/backend && ./gradlew clean

# Reset test state (local)
reset:
	curl -X POST http://localhost:8080/reset

# =============================================================================
# Local environment (backend + postgres + frontend)
# =============================================================================

# Start backend + postgres locally (Docker)
local-up:
	cd deployment/envs/local && docker compose up --build -d

# Stop local environment
local-down:
	cd deployment/envs/local && docker compose down

# Backend logs (local)
local-logs:
	cd deployment/envs/local && docker compose logs -f fikua-lab

# Serve frontend locally (landing:3000, portal:3001, issuer:3002, cert:3003, wallet:3004, verifier:3005)
local-frontend:
	chmod +x deployment/envs/local/deploy-frontend.sh && ./deployment/envs/local/deploy-frontend.sh

# =============================================================================
# VPS — Docker (build + push)
# =============================================================================

# Build + push to DockerHub (version tag from gradle.properties + latest)
docker-push:
	chmod +x deployment/envs/dev/release-docker.sh && ./deployment/envs/dev/release-docker.sh

# =============================================================================
# VPS — Deploy
# =============================================================================

# Deploy backend to VPS (pull image + restart)
deploy:
	./deployment/envs/dev/deploy-backend.sh deploy

# Deploy frontend to VPS (upload static files)
deploy-frontend:
	chmod +x deployment/envs/dev/deploy-frontend.sh && ./deployment/envs/dev/deploy-frontend.sh

# Deploy nginx config + SSL to VPS
deploy-nginx:
	chmod +x deployment/envs/dev/deploy-nginx.sh && ./deployment/envs/dev/deploy-nginx.sh

# Full deploy: cleanup + nginx + backend
full-deploy:
	./deployment/envs/dev/deploy-backend.sh full-deploy

# Cleanup old Docker resources on VPS
cleanup:
	./deployment/envs/dev/deploy-backend.sh cleanup

# =============================================================================
# VPS — Operations
# =============================================================================

# SSH into VPS
ssh:
	./deployment/envs/dev/deploy-backend.sh ssh

# View backend logs on VPS
logs:
	./deployment/envs/dev/deploy-backend.sh logs

# Check VPS status
status:
	./deployment/envs/dev/deploy-backend.sh status

# Backup PostgreSQL from VPS
backup:
	./deployment/envs/dev/deploy-backend.sh backup

# Reset VPS deployment (dangerous!)
vps-reset:
	./deployment/envs/dev/deploy-backend.sh reset

# =============================================================================
# Git Sync
# =============================================================================

# Colors
YELLOW := \033[0;33m
GREEN := \033[0;32m
NC := \033[0m

# Pull changes from remote
pull:
	@echo "$(YELLOW)Pulling changes from remote...$(NC)"
	@git pull || echo "$(YELLOW)Could not pull$(NC)"
	@echo "$(GREEN)Pull completed$(NC)"

# Commit and push all changes
push:
	@echo "$(YELLOW)Pushing changes...$(NC)"
	@git add .
	@git commit -m "Auto-sync $$(date '+%Y-%m-%d %H:%M')" || echo "$(YELLOW)No changes to commit$(NC)"
	@git push || echo "$(YELLOW)Could not push$(NC)"
	@echo "$(GREEN)Push completed$(NC)"
