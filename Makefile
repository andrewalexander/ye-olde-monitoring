# Pure-Go SQLite means no cgo, so a Mac can cross-compile a static Linux binary.
#
#   make dist ARCH=arm64                  # just build dist/dnscount-linux-arm64
#   make deploy HOST=me@homeserver        # build, copy, install/upgrade over ssh
#   make deploy HOST=me@homeserver ARCH=arm64

ARCH ?= amd64
HOST ?=
BIN  := dist/dnscount-linux-$(ARCH)

.PHONY: build test dist deploy clean up smoke down

build:
	go build ./...

test:
	go test -race ./...

dist:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) go build -trimpath -ldflags='-s -w' -o $(BIN) ./cmd/dnscount

deploy: test dist
	@test -n "$(HOST)" || (echo "usage: make deploy HOST=user@host [ARCH=amd64|arm64]" && exit 2)
	ssh $(HOST) 'rm -rf /tmp/dnscount-deploy && mkdir -p /tmp/dnscount-deploy'
	scp -q $(BIN) $(HOST):/tmp/dnscount-deploy/dnscount
	scp -qr deploy/systemd deploy/dnscount.env.example deploy/install.sh $(HOST):/tmp/dnscount-deploy/
	ssh -t $(HOST) 'sudo sh /tmp/dnscount-deploy/install.sh /tmp/dnscount-deploy'

clean:
	rm -rf dist

# Local stack (docker-compose.yml; or `tilt up`).
up:
	docker compose up --build -d

smoke:
	sh scripts/smoke.sh

down:
	docker compose down -v
