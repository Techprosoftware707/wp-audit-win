# wp-audit-win developer Makefile
SHELL := /bin/bash
COMPOSE := docker compose

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS=":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: up
up: ## Start the base stack (detached)
	$(COMPOSE) up -d --build

.PHONY: scanners
scanners: ## Start base stack + heavy scanner workers (wpscan/zap/wpcli)
	$(COMPOSE) --profile scanners up -d --build

.PHONY: down
down: ## Stop the stack
	$(COMPOSE) down

.PHONY: logs
logs: ## Tail logs
	$(COMPOSE) logs -f --tail=100

.PHONY: migrate
migrate: ## Run DB migrations
	$(COMPOSE) exec api alembic upgrade head

.PHONY: bootstrap
bootstrap: ## Create the initial admin user from env
	$(COMPOSE) exec api python -m app.cli.bootstrap

.PHONY: health
health: ## Run the health check script
	./scripts/health-check.sh

# ---- local dev (no docker) ----
.PHONY: dev-backend
dev-backend: ## Run the API locally (SQLite, needs backend deps installed)
	cd backend && WPSEC_ENV=development uvicorn app.main:app --reload --port 8000

.PHONY: test
test: ## Run the backend test suite (SQLite + fake queue, no services needed)
	cd backend && python -m pytest -q

.PHONY: lint
lint: ## Lint backend
	cd backend && ruff check app tests || true

.PHONY: fmt
fmt: ## Format backend
	cd backend && ruff format app tests || true
