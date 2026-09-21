.PHONY: install run lint format test clean

install:
	uv sync

run:
	docker compose up --build --watch identity-service
	docker image prune -f

lint:
	uv run ruff check .

lint-fix:
	uv run ruff check . --fix

format:
	uv run ruff format .

test:
	@if ! nc -z 127.0.0.1 8080 2>/dev/null && ! curl -s http://127.0.0.1:8080/ >/dev/null 2>&1; then \
		echo "Starting Firestore emulator..."; \
		docker compose up -d firestore; \
		echo "Waiting for Firestore emulator to be ready..."; \
		for i in $$(seq 1 30); do \
			if nc -z 127.0.0.1 8080 2>/dev/null || curl -s http://127.0.0.1:8080/ >/dev/null 2>&1; then \
				echo "Firestore emulator is ready!"; \
				break; \
			fi; \
			sleep 1; \
		done; \
		STOP_EMULATOR=1; \
	fi; \
	PYTHONPATH=. uv run pytest tests/ -v; \
	STATUS=$$?; \
	if [ "$$STOP_EMULATOR" = "1" ]; then \
		docker compose down; \
	fi; \
	exit $$STATUS

clean:
	rm -rf __pycache__
	rm -rf .ruff_cache
	rm -rf .pytest_cache
	find . -type d -name "__pycache__" -exec rm -rf {} +
	docker compose down --rmi local
	docker image prune -f
