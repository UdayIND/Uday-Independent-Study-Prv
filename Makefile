.PHONY: setup run test clean help docker-build docker-up docker-down verify

# Variables
PYTHON := python3
PIP := pip3
DOCKER_COMPOSE := docker compose
PCAP :=

help:
	@echo "Available targets:"
	@echo "  setup          - Install dependencies and setup pre-commit hooks"
	@echo "  run PCAP=...    - Run the pipeline on a PCAP file"
	@echo "  test            - Run pytest test suite"
	@echo "  clean           - Remove generated files and caches"
	@echo "  docker-build    - Build Docker images"
	@echo "  docker-up       - Start Docker services"
	@echo "  docker-down     - Stop Docker services"
	@echo "  lint            - Run linting checks"
	@echo "  format          - Format code with black"

setup:
	@if [ ! -d "venv" ]; then \
		echo "Creating virtual environment..."; \
		$(PYTHON) -m venv venv; \
	fi
	@echo "Installing dependencies..."
	@. venv/bin/activate && $(PIP) install -e ".[dev]"
	@. venv/bin/activate && pre-commit install || echo "Pre-commit installation skipped"
	@echo ""
	@echo "Setup complete! Activate the virtual environment with:"
	@echo "  source venv/bin/activate"
	@echo ""
	@echo "Or run commands with: . venv/bin/activate && <command>"

run:
ifndef PCAP
	@echo "Error: PCAP variable must be set. Usage: make run PCAP=data/raw/example.pcap"
	@exit 1
endif
	@if [ ! -f "$(PCAP)" ]; then \
		echo "Error: PCAP file $(PCAP) not found"; \
		exit 1; \
	fi
	@if [ -d "venv" ]; then \
		. venv/bin/activate && bash scripts/run_with_docker.sh "$(PCAP)"; \
	else \
		bash scripts/run_with_docker.sh "$(PCAP)"; \
	fi

test:
	@if [ -d "venv" ]; then \
		. venv/bin/activate && pytest tests/ -v; \
	else \
		pytest tests/ -v; \
	fi

clean:
	find . -type d -name "__pycache__" -exec rm -r {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -r {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -r {} + 2>/dev/null || true
	find . -type d -name ".coverage" -exec rm -r {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -r {} + 2>/dev/null || true
	rm -rf dist/ build/
	@echo "Clean complete!"

docker-build:
	$(DOCKER_COMPOSE) build

docker-up:
	$(DOCKER_COMPOSE) up -d

docker-down:
	$(DOCKER_COMPOSE) down

lint:
	ruff check src/ tests/
	mypy src/

format:
	black src/ tests/

verify:
	@bash scripts/verify_run.sh
