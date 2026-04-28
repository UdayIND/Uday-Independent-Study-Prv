.PHONY: setup test train evaluate ingest serve ui clean reproduce lint help

PYTHON := python3
PIP := pip3

help:  ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

setup:  ## Install all dependencies
	@if [ ! -d "venv" ]; then \
		echo "Creating virtual environment..."; \
		$(PYTHON) -m venv venv; \
	fi
	@echo "Installing dependencies..."
	@. venv/bin/activate && $(PIP) install -e ".[dev]"
	@echo "Setup complete! Activate with: source venv/bin/activate"

test:  ## Run the test suite
	@. venv/bin/activate && pytest tests/ -v

train:  ## Train the PPO policy (default: 2 iterations)
	@. venv/bin/activate && python -m src.model.train

train-full:  ## Train PPO with paper parameters (200 iterations, 5 seeds)
	@. venv/bin/activate && python -m src.model.train --num-iterations 200 --num-seeds 5

ingest:  ## Ingest LANL auth.txt into Neo4j
	@. venv/bin/activate && python -m src.ingest.lanl_loader --auth-path data/lanl/auth.txt

evaluate:  ## Evaluate trained PPO policy (Table III)
	@. venv/bin/activate && python scripts/evaluate.py --checkpoint data/models/ppo_policy_checkpoint

benchmark:  ## Run ingestion benchmark (Table II)
	@. venv/bin/activate && python scripts/ingest_lanl.py

serve:  ## Start the FastAPI policy endpoint
	@. venv/bin/activate && uvicorn src.api:app --host 0.0.0.0 --port 8000 --reload

ui:  ## Start the Streamlit analyst workbench
	@. venv/bin/activate && streamlit run src/ui/app.py --server.port 8501

download-data:  ## Download the LANL dataset
	@bash scripts/download_lanl.sh

reproduce:  ## Run full reproduction pipeline
	@bash reproduce.sh

lint:  ## Run linters (ruff + black check)
	@. venv/bin/activate && ruff check src/ tests/ && black --check src/ tests/

format:  ## Format code (black + ruff fix)
	@. venv/bin/activate && black src/ tests/ && ruff check --fix src/ tests/

clean:  ## Remove build artifacts, caches, and checkpoints
	@find . -type d -name "__pycache__" -exec rm -r {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "*.egg-info" -exec rm -r {} + 2>/dev/null || true
	@find . -type d -name ".pytest_cache" -exec rm -r {} + 2>/dev/null || true
	@rm -rf dist/ build/ htmlcov/ .coverage
	@echo "Clean complete!"
