VENV = /tmp/acme-test-venv
PYTHON = $(VENV)/bin/python3
PYTEST = $(VENV)/bin/pytest

.PHONY: all test lint check docker-build clean venv

all: test lint

venv:
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install -q -r dev-requirements.txt

test: venv
	$(PYTEST) -v

lint: venv
	$(PYTHON) -m py_compile app/*.py tests/*.py

check: venv lint test

docker-build:
	docker compose build

clean:
	rm -rf $(VENV)
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
