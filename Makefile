.PHONY: install build run lint test bench clean

install:
	go mod download

build:
	go build -o bin/identity-service cmd/server/main.go

run:
	go run cmd/server/main.go

lint:
	go vet ./...

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
	FIRESTORE_EMULATOR_HOST=127.0.0.1:8080 GOOGLE_CLOUD_PROJECT=test-project ENVIRONMENT=testing go test -v -count=1 ./...; \
	STATUS=$$?; \
	if [ "$$STOP_EMULATOR" = "1" ]; then \
		docker compose down; \
	fi; \
	exit $$STATUS

bench: build
	go build -o bin/benchmark cmd/benchmark/main.go
	./bin/benchmark

clean:
	rm -rf bin
	docker compose down --rmi local
	docker image prune -f
