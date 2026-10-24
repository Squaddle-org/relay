VECTORS := $(CURDIR)/.spec/testvectors

.PHONY: vectors test lint run image
vectors:
	./scripts/fetch-spec.sh $(VECTORS)

test: vectors
	SQUADDLE_TESTVECTORS=$(VECTORS) go test ./...

lint:
	gofmt -l . | (! grep .) && go vet ./...

run:
	go run ./cmd/relay -db ./dev.db -listen :8080 -metrics :9090 -limits none

image:
	docker build -t ghcr.io/squaddle-org/relay:dev .
