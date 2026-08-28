.PHONY: install test validate demo run clean

install:
	python -m pip install -e '.[demo,dev]'

test:
	# The census, not bare pytest: pytest reports the tests, the census is
	# the gate, and they can disagree (undeclared skips exit 0 under pytest).
	python scripts/check_test_coverage.py

validate:
	python scripts/validate_repository.py

demo:
	nornyx-forge demo --offline

run:
	uvicorn demo_app.main:app --host 0.0.0.0 --port 8000

clean:
	rm -rf .pytest_cache .ruff_cache build dist *.egg-info .nornyx/runs
