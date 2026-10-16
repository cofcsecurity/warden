BINARY := warden
GOOS ?= linux
GOARCH ?= amd64

# Nothing per-competition is compiled in: every setting lives in the
# runtime config that `warden install` writes on the box.
LDFLAGS := -s -w

.PHONY: build release test vet fmt e2e clean

build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags="$(LDFLAGS)" -o bin/$(BINARY) ./cmd/warden

# release builds every published binary plus SHA256SUMS into dist/.
release:
	rm -rf dist && mkdir -p dist
	for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BINARY)-linux-$$arch ./cmd/warden || exit 1; \
	done
	cd dist && sha256sum $(BINARY)-* > SHA256SUMS

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

# e2e runs the container end-to-end tests (needs Docker).
e2e:
	./test/e2e/run.sh

clean:
	rm -rf bin/ dist/
