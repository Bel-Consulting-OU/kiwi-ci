.PHONY: build test lint fmt run clean

build:
	go build -trimpath -o dist/kiwi ./cmd/kiwi

test:
	go test ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

lint:
	go vet ./...

run:
	go run ./cmd/kiwi run -f examples/kiwi.yaml

clean:
	rm -rf dist .kiwi/cache .kiwi/artifacts .kiwi/runs
