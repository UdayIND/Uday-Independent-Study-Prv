.PHONY: setup run test clean verify preflight eval

PYTHON := python3
PIP := pip3

setup:
	@if [ ! -d "venv" ]; then \
		echo "Creating virtual environment..."; \
		$(PYTHON) -m venv venv; \
	fi
	@echo "Installing dependencies..."
	@. venv/bin/activate && $(PIP) install -e ".[dev]"
	@. venv/bin/activate && pre-commit install || echo "Pre-commit installation skipped"
	@echo "Setup complete! Activate with: source venv/bin/activate"

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

verify:
	@bash scripts/verify_run.sh

preflight:
	@bash scripts/preflight.sh

clean:
	@find . -type d -name "__pycache__" -exec rm -r {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "*.egg-info" -exec rm -r {} + 2>/dev/null || true
	@find . -type d -name ".pytest_cache" -exec rm -r {} + 2>/dev/null || true
	@rm -rf dist/ build/ htmlcov/ .coverage
	@echo "Clean complete!"

eval:
	@LATEST_RUN=$$(ls -t reports/runs/ 2>/dev/null | head -1); \
	if [ -z "$$LATEST_RUN" ]; then \
		echo "Error: No run directories found in reports/runs/"; \
		exit 1; \
	fi; \
	echo "Evaluating run: $$LATEST_RUN"; \
	if [ -d "venv" ]; then \
		. venv/bin/activate && python3 -c "from src.eval.evaluator import Evaluator; import pandas as pd; import json; from pathlib import Path; run_dir = Path('reports/runs/$$LATEST_RUN'); events_df = pd.read_parquet(run_dir / 'events.parquet'); detections = [json.loads(line) for line in open(run_dir / 'detections.jsonl') if line.strip()]; cases = []; eval = Evaluator(run_dir); eval.evaluate(events_df, detections, cases)"; \
	else \
		python3 -c "from src.eval.evaluator import Evaluator; import pandas as pd; import json; from pathlib import Path; run_dir = Path('reports/runs/$$LATEST_RUN'); events_df = pd.read_parquet(run_dir / 'events.parquet'); detections = [json.loads(line) for line in open(run_dir / 'detections.jsonl') if line.strip()]; cases = []; eval = Evaluator(run_dir); eval.evaluate(events_df, detections, cases)"; \
	fi
