GO ?= go
STATICCHECK_VERSION ?= 2025.1.1
GOVULNCHECK_VERSION ?= latest
COVER_MIN ?= 85

.PHONY: all build test test-race cover fmt fmt-check vet lint staticcheck vuln check \
        test-integration e2e e2e-ci tidy-check clean

all: check

build:
	$(GO) build ./...

test:
	$(GO) test ./... -count=1

test-race:
	$(GO) test ./... -count=1 -race

# Writes coverage.out and fails below $(COVER_MIN)% total coverage.
cover:
	$(GO) test ./... -count=1 -race -covermode=atomic -coverprofile=coverage.out
	@$(GO) tool cover -func=coverage.out | tail -1
	@$(GO) tool cover -func=coverage.out | awk -v min=$(COVER_MIN) '/^total:/ { sub("%","",$$3); if ($$3+0 < min) { printf "coverage %s%% < %s%%\n", $$3, min; exit 1 } }'

fmt:
	gofmt -w .

fmt-check:
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo "gofmt: files need formatting (run make fmt)" && exit 1)

vet:
	$(GO) vet ./...
	$(GO) vet -tags=integration ./...

staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...
	$(GO) run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) -tags=integration ./test/...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

# The library must stay dependency-free (see AGENTS.md).
tidy-check:
	$(GO) mod tidy -diff
	@test ! -f go.sum || (echo "go.sum exists: bomhort-go must not have dependencies" && exit 1)

lint: fmt-check vet staticcheck tidy-check

# Everything CI runs except the E2E stack.
check: lint test-race build

# Requires a running BOMHort with AUTH_ENABLED=true:
#   BOMHORT_URL=http://localhost:18080 BOMHORT_API_KEY=... make test-integration
test-integration:
	$(GO) test ./test/integration/ -count=1 -tags=integration -v -timeout 20m

# Full stack via docker compose; needs BOMHORT_SRC (a BOMHort checkout).
e2e:
	./hack/e2e-bomhort.sh

# Same as CI (.github/workflows/e2e.yml): build BOMHort images from $(BOMHORT_SRC).
e2e-ci:
	BOMHORT_BUILD=1 BOMHORT_IMAGE_TAG=ci ./hack/e2e-bomhort.sh

clean:
	rm -rf .e2e coverage.out
