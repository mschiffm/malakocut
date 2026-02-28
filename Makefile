.PHONY: build test clean

build:
	go build -o malakocut ./cmd/malakocut

test:
	go test -v ./internal/malako/...

clean:
	rm -f malakocut
	rm -f malakocut_debug.log
	rm -rf /tmp/malakocut-test-*
