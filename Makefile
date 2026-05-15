.DEFAULT_GOAL := help

COMPOSE := docker compose
BACKEND := $(COMPOSE) exec api
ALEMBIC := $(BACKEND) alembic

.PHONY: help run dev build up down logs migrate migrate-create seed check-tools test lint clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-20s\033[0m %s\n",$$1,$$2}'

run: dev ## Alias for dev (start all services with live reload)

dev: ## Start all services in dev mode (with live reload)
	cp -n .env.example .env 2>/dev/null || true
	$(COMPOSE) up --build

build: ## Build all Docker images
	$(COMPOSE) build

up: ## Start all services (detached)
	$(COMPOSE) up -d

down: ## Stop all services
	$(COMPOSE) down

down-volumes: ## Stop all services and remove volumes
	$(COMPOSE) down -v

logs: ## Follow logs for all services
	$(COMPOSE) logs -f

logs-api: ## Follow API logs
	$(COMPOSE) logs -f api

logs-worker: ## Follow worker logs
	$(COMPOSE) logs -f worker-dast worker-sast worker-ai worker-report

migrate: ## Run Alembic migrations
	$(ALEMBIC) upgrade head

migrate-create: ## Create a new migration (usage: make migrate-create MSG="description")
	$(ALEMBIC) revision --autogenerate -m "$(MSG)"

migrate-down: ## Downgrade one migration
	$(ALEMBIC) downgrade -1

seed: ## Seed the database with initial data
	$(BACKEND) python scripts/seed_db.py

check-tools: ## Verify all security tools are installed
	$(BACKEND) python scripts/check_tools.py

setup: ## First-time setup: copy env, build, start, migrate, seed
	@[ -f .env ] || cp .env.example .env
	@echo "⚠️  Edit .env and set SECRET_KEY before continuing"
	@read -p "Press Enter when done editing .env..." dummy
	$(COMPOSE) up -d postgres redis
	sleep 5
	$(COMPOSE) up -d --build
	sleep 10
	$(MAKE) migrate
	$(MAKE) seed
	@echo ""
	@echo "✅ AutoPentest is running at http://localhost:3000"
	@echo "   Admin credentials are in the seed output above."

test: ## Run backend tests
	$(BACKEND) python -m pytest tests/ -v

lint: ## Run linters
	$(BACKEND) python -m ruff check .
	$(BACKEND) python -m mypy .

shell: ## Open a shell in the API container
	$(BACKEND) /bin/bash

psql: ## Open psql in the postgres container
	$(COMPOSE) exec postgres psql -U autopentest -d autopentest

redis-cli: ## Open redis-cli
	$(COMPOSE) exec redis redis-cli

clean: ## Remove build artifacts and __pycache__
	find ./backend -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find ./backend -name "*.pyc" -delete 2>/dev/null || true
	find ./frontend -name ".next" -type d -exec rm -rf {} + 2>/dev/null || true
