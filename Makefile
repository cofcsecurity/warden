BINARY := warden
GOOS ?= linux
GOARCH ?= amd64

# Per-competition values, baked in at build time rather than shipped as a
# config file. Override on the make invocation, e.g.:
#   make build TEAM_PUBKEY="ssh-ed25519 AAAA..." TEAM_FROM_IP=10.0.0.5 \
#              TOTP_SECRET=... REPLICATE_KEY=$$(base64 -i replicate_key) \
#              REPLICATE_TARGETS='ssh://warden@boxB/from-A||ssh-ed25519 AAAA hostB;;ssh://warden@boxF/from-A||ssh-ed25519 AAAA hostF'
#
# REPLICATE_TARGETS is one or more "<url>||<hostkey>" pairs separated by
# ";;" — one entry per replication peer (see docs/DEPLOYMENT.md's
# "Replication topology" for setting up a multi-box mesh). <hostkey> is
# empty for a file:// target (removable media), which also needs no
# REPLICATE_KEY. Every ssh:// target shares the one REPLICATE_KEY.
#
# AUTOBAN_ENABLED opts into watch's auto-ban reaction (docs/DESIGN.md's
# "Active Response" section) — leave it empty unless the team has
# confirmed firewalling an attacker IP is allowed under this
# competition's rules of engagement. Any non-empty value turns it on.
TEAM_PUBKEY ?=
TEAM_FROM_IP ?=
TOTP_SECRET ?=
REPLICATE_TARGETS ?=
REPLICATE_KEY ?=
AUTOBAN_ENABLED ?=

LDFLAGS := -s -w \
	-X 'main.buildTeamPubKey=$(TEAM_PUBKEY)' \
	-X 'main.buildTeamFromIP=$(TEAM_FROM_IP)' \
	-X 'main.buildTOTPSecret=$(TOTP_SECRET)' \
	-X 'main.buildReplicateTargets=$(REPLICATE_TARGETS)' \
	-X 'main.buildReplicateKey=$(REPLICATE_KEY)' \
	-X 'main.buildAutobanEnabled=$(AUTOBAN_ENABLED)'

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
