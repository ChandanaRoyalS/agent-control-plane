.DEFAULT_GOAL := help
.PHONY: help install check fmt lint types test cov clean image up down logs smoke \
        identity-smoke token idp-reset probe-resource probe-cimd prove-passthrough prove-cache prove-refusal prove-predispatch corpus

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-10s\033[0m %s\n", $$1, $$2}'

install:  ## Install dependencies and git hooks
	uv sync --all-groups
	uv run pre-commit install

check: lint types test  ## Everything CI runs, in the same order

fmt:  ## Apply formatting and safe autofixes
	uv run ruff format .
	uv run ruff check --fix .

lint:  ## Lint and verify formatting
	uv run ruff check .
	uv run ruff format --check .

types:  ## Strict type check
	uv run mypy

test:  ## Run the test suite with coverage
	uv run pytest

cov:  ## Open the HTML coverage report
	uv run pytest --cov-report=html
	@echo "open htmlcov/index.html"

image:  ## Build the container images
	docker compose build

up:  ## Bring up the whole stack and wait until it is ready
	docker compose up -d --wait gateway
	@echo "gateway :8080  admin :9090  jaeger :16686  keycloak :8081 (admin/admin)"
	@echo "the gateway now authenticates — 'make token' for one, 'make identity-smoke' to prove it"

down:  ## Tear the stack down, volumes included
	docker compose down -v --remove-orphans

logs:  ## Follow the gateway's logs
	docker compose logs -f gateway

smoke:  ## Assert the composed stack actually works
	uv run python scripts/compose_smoke.py

identity-smoke:  ## Assert the identity stack works against the real Keycloak
	uv run python scripts/identity_smoke.py

prove-passthrough:  ## Break the no-passthrough invariant on purpose, and check the test notices
	uv run python scripts/mutate_no_passthrough.py

prove-cache:  ## Break the result cache's isolation on purpose, and check the test notices
	uv run python scripts/mutate_result_cache.py

prove-refusal:  ## Break the firewall's refusal on purpose, and check the tests notice
	uv run python scripts/mutate_refusal.py

prove-predispatch:  ## Hunt for a call the pre-dispatch check refuses and policy allows
	uv run python scripts/prove_predispatch.py

corpus:  ## What the benign corpus contains, and what the firewall does to it
	uv run python scripts/corpus_stats.py

probe-resource:  ## Measure what Keycloak does with RFC 8707's `resource`
	uv run python scripts/probe_resource_indicator.py

probe-cimd:  ## Measure whether Keycloak accepts a URL client_id (CIMD)
	uv run python scripts/probe_cimd.py

token:  ## Print an access token for alice (USER=bob for the other one)
	@uv run python scripts/keycloak_token.py $(or $(USER),alice)

# Keycloak skips the import when the realm already exists, which is the right
# default and the reason editing config/keycloak/acp-realm.json appears to do
# nothing. There is no database volume (see docker-compose.yml), so the realm
# lives in the container's own layer and recreating the container is enough —
# but a plain `restart` is not, which is the whole reason this target exists.
idp-reset:  ## Re-import config/keycloak after editing it
	docker compose rm -sf keycloak
	docker compose up -d --wait gateway

clean:  ## Remove caches and build artifacts
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage coverage.xml
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
