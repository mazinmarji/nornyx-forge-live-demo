.PHONY: install test validate demo run clean

install:
	python -m pip install -e '.[demo,dev]'

test:
	pytest

validate:
	python scripts/validate_repository.py

demo:
	nornyx-forge demo --offline

run:
	uvicorn demo_app.main:app --host 0.0.0.0 --port 8000

clean:
	rm -rf .pytest_cache .ruff_cache build dist *.egg-info .nornyx/runs
