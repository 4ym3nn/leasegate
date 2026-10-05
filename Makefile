.PHONY: build test check demo clean-services
build:
	CGO_ENABLED=0 go build -trimpath -o bin/leasegate ./cmd/leasegate
test:
	go test -race ./...
check:
	go vet ./...
	test -z "$$(gofmt -l cmd internal)"
demo: build
	bash scripts/demo.sh
clean-services:
	docker compose --env-file .local/demo.env down
