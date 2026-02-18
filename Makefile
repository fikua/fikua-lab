# Fikua Lab — build and deployment shortcuts

.PHONY: help build run test clean compile local-up local-down local-logs local-frontend \
        integration-test load-test \
        docker-push deploy deploy-frontend deploy-nginx full-deploy \
        cleanup ssh logs status backup vps-reset reset \
        local-db-reset vps-db-reset \
        pull push

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
	@echo "  Testing (k6)"
	@echo "  ------------"
	@echo "  make integration-test  Docker up + k6 integration tests + down"
	@echo "  make load-test         k6 load/performance tests (backend running)"
	@echo ""
	@echo "  Local environment"
	@echo "  -----------------"
	@echo "  make local-up         Start backend + postgres (Docker Compose)"
	@echo "  make local-down       Stop local environment"
	@echo "  make local-logs       Tail backend logs (local)"
	@echo "  make local-frontend   Serve frontend locally (ports 3000-3005)"
	@echo "  make local-db-reset   Drop all tables and restart (local)"
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
	@echo "  make vps-db-reset     Drop all tables on VPS and restart backend"
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
# Integration & load tests
# =============================================================================

# Full cycle: compose up → k6 integration tests → compose down
integration-test:
	@docker compose -f deployment/envs/local/compose.yaml up --build -d
	@echo "Waiting for backend..."
	@READY=0; for i in $$(seq 1 30); do \
		if curl -sf http://localhost:8080/health > /dev/null 2>&1; then READY=1; break; fi; \
		sleep 2; \
	done; \
	if [ "$$READY" -ne 1 ]; then \
		echo "Backend did not start within 60s"; \
		docker compose -f deployment/envs/local/compose.yaml logs --tail=30 fikua-lab; \
		docker compose -f deployment/envs/local/compose.yaml down; \
		exit 1; \
	fi
	k6 run suite/k6/tests/integration.js; \
	EXIT_CODE=$$?; \
	docker compose -f deployment/envs/local/compose.yaml down; \
	exit $$EXIT_CODE

# Load/performance tests (requires backend running at localhost:8080)
load-test:
	k6 run suite/k6/tests/load.js

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

# Drop all tables and restart backend (local) — profiles re-seeded on restart
local-db-reset:
	@echo "Dropping all tables in local database..."
	@docker compose -f deployment/envs/local/compose.yaml exec postgres \
		psql -U fikua -d fikua -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
	@echo "Restarting backend to re-run migrations..."
	@docker compose -f deployment/envs/local/compose.yaml restart fikua-lab
	@echo "Local DB reset complete. Profiles re-seeded."

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

# Drop all tables on VPS and restart backend — profiles re-seeded on restart
vps-db-reset:
	@echo "Dropping all tables on VPS database..."
	@ssh -i deployment/envs/dev/ssh/id_ed25519 -o StrictHostKeyChecking=no -p 49222 \
		ubuntu@51.38.179.236 "sudo docker exec fikua-lab-db psql -U fikua -d fikua \
		-c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;' && \
		sudo docker restart fikua-lab"
	@echo "VPS DB reset complete. Waiting for backend..."
	@READY=0; for i in $$(seq 1 20); do \
		if curl -sf https://issuer.lab.fikua.com/health > /dev/null 2>&1; then READY=1; break; fi; \
		sleep 3; \
	done; \
	if [ "$$READY" -eq 1 ]; then echo "Backend is UP. Profiles re-seeded."; \
	else echo "WARNING: Backend did not come back within 60s"; fi

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
