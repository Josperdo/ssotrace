# ssotrace build and maintenance tasks. Run `make` or `make help` for a list.

.DEFAULT_GOAL := help

# Version stamps injected into the binary at link time.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
# Commit time rather than wall-clock time, so two builds of the same commit
# produce the same binary.
DATE    ?= $(shell git log -1 --format=%cI 2>/dev/null || echo unknown)

LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

LAB_COMPOSE := docker compose -f lab/docker-compose.yml --env-file lab/.env

.PHONY: help build test golden fuzz demo demo-docker lint vuln fmt tidy check hooks lab-up lab-down clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  %-10s %s\n", $$1, $$2}'

build: ## Build a static binary to bin/ssotrace
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ssotrace ./cmd/ssotrace

test: ## Run tests with the race detector
	go test -race -count=1 ./...

# -update is defined only by packages that have golden files; passing it to
# ./... would fail every other test binary with "flag provided but not defined".
GOLDEN_PKGS := ./internal/report

golden: ## Rewrite golden files in testdata/golden (review the diff after)
	go test -count=1 $(GOLDEN_PKGS) -update
	git diff --stat -- testdata/golden

# Each fuzz target as "package:Target". go test can fuzz only one target per
# run, so they run one after another.
FUZZ_TARGETS := ./internal/har:FuzzDecode ./internal/saml:FuzzParse ./internal/saml:FuzzDecodeRedirect ./internal/diagnose:FuzzDiagnose ./internal/redact:FuzzRedactLeavesNoSecrets
FUZZTIME ?= 30s

fuzz: ## Fuzz every target for FUZZTIME each (default 30s), e.g. make fuzz FUZZTIME=10m
	@fail=0; for t in $(FUZZ_TARGETS); do \
		pkg=$${t%%:*}; name=$${t#*:}; \
		echo "== $$name ($$pkg, $(FUZZTIME))"; \
		go test -run '^$$' -fuzz "^$$name\$$" -fuzztime $(FUZZTIME) "$$pkg" || fail=1; \
	done; exit $$fail

lint: ## Run golangci-lint
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not found: brew install golangci-lint"; exit 1; }
	golangci-lint run

vuln: ## Check dependencies and stdlib for known vulnerabilities
	@command -v govulncheck >/dev/null 2>&1 || { echo "govulncheck not found: go install golang.org/x/vuln/cmd/govulncheck@latest"; exit 1; }
	govulncheck ./...

fmt: ## Format code and run go vet
	gofmt -s -w .
	go vet ./...

tidy: ## Tidy go.mod and go.sum
	go mod tidy

check: fmt lint test vuln ## Everything that must pass before a change is done

hooks: ## Install git hooks from scripts/hooks
	git config core.hooksPath scripts/hooks
	@echo "git hooks installed from scripts/hooks"

demo: build ## Regenerate the demo capture and re-record docs/demo.gif (needs vhs)
	go test -count=1 ./internal/testutil -run TestDemoHAR -write-demo
	vhs docs/demo.tape

# The same recording without installing vhs: Charm's image already has vhs,
# ttyd, and ffmpeg. A Linux build of ssotrace is mounted over bin/ssotrace
# inside the container only; the local binary is untouched.
VHS_IMAGE := ghcr.io/charmbracelet/vhs:v0.12.1

demo-docker: build ## Same as demo, but runs vhs in Docker (no local vhs needed)
	go test -count=1 ./internal/testutil -run TestDemoHAR -write-demo
	mkdir -p dist/demo
	CGO_ENABLED=0 GOOS=linux GOARCH=$$(docker image inspect --format '{{.Architecture}}' $(VHS_IMAGE) 2>/dev/null || (docker pull -q $(VHS_IMAGE) >/dev/null && docker image inspect --format '{{.Architecture}}' $(VHS_IMAGE))) \
		go build -trimpath -o dist/demo/ssotrace ./cmd/ssotrace
	docker run --rm -v "$$PWD:/vhs" -v "$$PWD/dist/demo/ssotrace:/vhs/bin/ssotrace:ro" $(VHS_IMAGE) docs/demo.tape

lab-up: ## Start the local Keycloak + SP lab (needs lab/.env)
	@test -f lab/.env || { echo "lab/.env missing: cp lab/.env.example lab/.env and edit it"; exit 1; }
	$(LAB_COMPOSE) up -d --build

lab-down: ## Stop the local lab and discard its state
	$(LAB_COMPOSE) down

clean: ## Remove build output
	rm -rf bin/ dist/ coverage.out
