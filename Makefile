PY=python
PIP=$(PY) -m pip
PKG=odin-webhook-sentinel

.PHONY: install dev lint fmt test coverage docker run clean

install:
	$(PIP) install --upgrade pip
	$(PIP) install .

dev: install
	$(PIP) install .[dev]

lint:
	$(PY) -m ruff check .

fmt:
	$(PY) -m ruff format .

test:
	pytest -q

coverage:
	pytest -q --cov=sentinel --cov=services --cov-report=term-missing

docker:
	docker build -t $(PKG):dev .

run:
	uvicorn services.sentinel.main:app --host 0.0.0.0 --port 8787

clean:
	rm -rf .pytest_cache .ruff_cache dist build *.egg-info coverage.xml
