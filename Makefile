BINARY := warden
GOOS ?= linux
GOARCH ?= amd64

# Per-competition values, baked in at build time rather than shipped as a
# config file. Override on the make invocation, e.g.:
#   make build TEAM_PUBKEY="ssh-ed25519 AAAA..." TEAM_FROM_IP=10.0.0.5 \
#              TOTP_SECRET=... REPLICATE_URL=ssh://warden@backup-box/warden \
#              REPLICATE_KEY=$$(base64 -i replicate_key) \
#              REPLICATE_HOST_KEY="$$(cat backup_box_host_key.pub)"
# REPLICATE_KEY/REPLICATE_HOST_KEY are only needed for an ssh:// target; a
# file:// target (removable media) needs neither.
TEAM_PUBKEY ?=
TEAM_FROM_IP ?=
TOTP_SECRET ?=
REPLICATE_URL ?=
REPLICATE_KEY ?=
REPLICATE_HOST_KEY ?=

LDFLAGS := -s -w \
	-X 'main.buildTeamPubKey=$(TEAM_PUBKEY)' \
	-X 'main.buildTeamFromIP=$(TEAM_FROM_IP)' \
	-X 'main.buildTOTPSecret=$(TOTP_SECRET)' \
	-X 'main.buildReplicateURL=$(REPLICATE_URL)' \
	-X 'main.buildReplicateKey=$(REPLICATE_KEY)' \
	-X 'main.buildReplicateHostKey=$(REPLICATE_HOST_KEY)'

.PHONY: build test vet fmt vendor clean

build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags="$(LDFLAGS)" -o bin/$(BINARY) ./cmd/warden

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

vendor:
	go mod vendor

clean:
	rm -rf bin/
