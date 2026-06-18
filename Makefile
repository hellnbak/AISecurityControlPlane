.PHONY: dev test check clean

dev:
	uvicorn app.main:app --host 127.0.0.1 --port 8787 --reload

test:
	pytest -q

check:
	python -m compileall -q app endpoint
	pytest -q

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
	rm -rf .pytest_cache
