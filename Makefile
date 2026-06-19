VENV = /tmp/acme-test-venv
PYTHON = $(VENV)/bin/python3
PYTEST = $(VENV)/bin/pytest

IMAGE = ghcr.io/ckyvra/acme-git-webhook
GIT_SHA = $(shell git rev-parse --short HEAD)
TAG ?= latest

.PHONY: all test lint typecheck check docker-build docker-push docker-push-sha clean venv

all: test lint typecheck

venv:
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install -q -r dev-requirements.txt

test: venv
	$(PYTEST) -v

test-integration: venv
	$(PYTEST) -v --run-integration

lint: venv
	$(VENV)/bin/ruff check .
	$(VENV)/bin/ruff format --check .

typecheck: venv
	$(VENV)/bin/mypy app/

check: venv lint typecheck test

docker-build:
	docker build -t $(IMAGE):$(TAG) .

docker-push: docker-build
	docker push $(IMAGE):$(TAG)

docker-push-sha: docker-build
	docker tag $(IMAGE):$(TAG) $(IMAGE):$(GIT_SHA)
	docker push $(IMAGE):$(GIT_SHA)
	docker push $(IMAGE):$(TAG)

clean:
	rm -rf $(VENV)
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
