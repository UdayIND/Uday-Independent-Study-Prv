.PHONY: setup run test clean verify preflight eval tune docker-rebuild benchmark ablation verify-all synthetic-pcaps

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
		. venv/bin/activate && python3 scripts/run_eval.py --run-dir "reports/runs/$$LATEST_RUN" --config configs/detector.yaml; \
	else \
		python3 scripts/run_eval.py --run-dir "reports/runs/$$LATEST_RUN" --config configs/detector.yaml; \
	fi

tune:
ifndef PCAP
	@echo "Error: PCAP variable must be set. Usage: make tune PCAP=data/raw/example.pcap"
	@exit 1
endif
	@if [ ! -f "$(PCAP)" ]; then \
		echo "Error: PCAP file $(PCAP) not found"; \
		exit 1; \
	fi
	@if [ -d "venv" ]; then \
		. venv/bin/activate && python3 scripts/tune_detectors.py --pcap "$(PCAP)"; \
	else \
		python3 scripts/tune_detectors.py --pcap "$(PCAP)"; \
	fi

docker-rebuild:
	@echo "Rebuilding Docker images..."
	@mkdir -p data/derived/zeek data/derived/suricata data/normalized reports/runs
	@docker compose build --no-cache
	@echo "Docker images rebuilt"

synthetic-pcaps:
	@echo "Generating synthetic PCAPs..."
	@if [ -d "venv" ]; then \
		. venv/bin/activate && python3 scripts/generate_synthetic_pcaps.py; \
	else \
		python3 scripts/generate_synthetic_pcaps.py; \
	fi

benchmark:
	@echo "Running benchmark suite..."
	@if [ -d "venv" ]; then \
		. venv/bin/activate && python3 scripts/run_benchmark.py; \
	else \
		python3 scripts/run_benchmark.py; \
	fi

ablation:
ifndef PCAP
	@echo "Error: PCAP variable must be set. Usage: make ablation PCAP=data/raw/example.pcap"
	@exit 1
endif
	@if [ ! -f "$(PCAP)" ]; then \
		echo "Error: PCAP file $(PCAP) not found"; \
		exit 1; \
	fi
	@if [ -d "venv" ]; then \
		. venv/bin/activate && python3 scripts/run_ablation.py --pcap "$(PCAP)"; \
	else \
		python3 scripts/run_ablation.py --pcap "$(PCAP)"; \
	fi

verify-all: verify
	@echo ""
	@echo "Checking additional outputs..."
	@if [ -d "reports/benchmark" ]; then \
		LATEST_BM=$$(ls -t reports/benchmark/ 2>/dev/null | head -1); \
		if [ -n "$$LATEST_BM" ] && [ -f "reports/benchmark/$$LATEST_BM/benchmark_report.md" ]; then \
			echo "Found: Benchmark report (reports/benchmark/$$LATEST_BM)"; \
		else \
			echo "Warning: No benchmark report found"; \
		fi; \
	else \
		echo "Warning: No benchmark directory found (run 'make benchmark')"; \
	fi
	@if [ -d "reports/ablation" ]; then \
		LATEST_AB=$$(ls -t reports/ablation/ 2>/dev/null | head -1); \
		if [ -n "$$LATEST_AB" ] && [ -f "reports/ablation/$$LATEST_AB/ablation_report.md" ]; then \
			echo "Found: Ablation report (reports/ablation/$$LATEST_AB)"; \
		else \
			echo "Warning: No ablation report found"; \
		fi; \
	else \
		echo "Warning: No ablation directory found (run 'make ablation PCAP=...')"; \
	fi
	@if [ -f "soc_pilot_proposal.md" ]; then \
		echo "Found: SOC pilot proposal"; \
	else \
		echo "Warning: SOC pilot proposal not found"; \
	fi
