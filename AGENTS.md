# Role & Project Context
You are an expert Senior Go Engineer specializing in API client libraries, supply-chain security (SBOM/VEX/OpenVEX) and testing against real services.

We are building **bomhort-go** (`github.com/seebom-labs/bomhort-go`): the Go client for the [BOMHort](https://github.com/seebom-labs/BOMHort) REST API. It covers the complete public API of BOMHort's api-gateway and ships `bomhorttest`, an in-memory fake gateway with BOMHort's real upload and VEX semantics. It was extracted from [VEXViper](https://github.com/seebom-labs/VEXViper)'s `internal/bomhort` (VEXViper `docs/INTEGRATION.md` §8); VEXViper and other BOMHort sidecars are its main consumers.

bomhort-go is a **client, not a fork**: it talks to BOMHort only through the public REST API and mirrors it — it never re-implements server features (SBOM parsing, OSV scanning, VEX ingestion) beyond what `bomhorttest` needs to model observable behaviour.

# Architecture Overview
One package plus a test double:

| File | Contents |
|------|----------|
| `bomhort.go` | Package doc, `Version`, `Client`, `Option`s, `New`, request core `do` (auth, rate limit, 429 retry, decode, strict decode) |
| `errors.go` | `APIError`, `StatusCode`, `Is*` helpers |
| `ratelimit.go` | Sliding-window `RateLimiter` (shared across goroutines/clients) |
| `pagination.go` | `Seq[T]`, `Paginate`, `Collect`, `DefaultWalkPageSize` |
| `types.go` | DTOs mirroring BOMHort `backend/pkg/dto/api.go` (JSON tags exactly as the server) |
| `sboms.go` | Health probes, SBOM list/iterate/find, detail, findings, dependencies, licenses, VEX, download, `PatchSBOMSource` |
| `upload.go` | `Upload`, `UploadSBOM`, `UploadVEX`, `UploadOptions` |
| `catalog.go` | Fleet-wide vulnerabilities and VEX, stats, search, packages, licenses |
| `projects.go` | Projects (+ unreleased detail/groups/sub-resources), tags, clusters, namespaces, fleet |
| `bomhorttest/` | Fake api-gateway (`Server`): auth, pagination, filters, uploads, VEX scoping/matching, PATCH, canned routes |
| `test/integration/` | `//go:build integration`; runs every endpoint against a live BOMHort with strict decoding |
| `hack/` | `e2e-bomhort.sh` + `docker-compose.e2e.yml`: isolated BOMHort stack on :18080, key `bomhort-go-e2e-key` |
| `docs/` | `API-COVERAGE.md`, `VEX.md`, `COMPATIBILITY.md`, `TESTING.md`, `MIGRATING-FROM-VEXVIPER.md`, `RELEASING.md` |
| `.github/workflows/` | `ci.yml` (lint, race tests on min+stable Go, coverage, govulncheck), `e2e.yml` (pinned BOMHort on PRs, + `main` weekly), `release.yml` (tag → checks → GitHub release → proxy) |

Source of truth for the API: BOMHort `backend/cmd/api-gateway/main.go` (routes, handlers), `backend/pkg/dto/api.go` (response types), `internal/vex/parser.go` + `cmd/parsing-worker/vex_scope.go` + `internal/clickhouse/queries_search.go` (VEX semantics). Read them before changing types or `bomhorttest` behaviour.

# Tech Stack
- **Language:** Go, `go.mod` `go 1.25.0`. Module path `github.com/seebom-labs/bomhort-go`.
- **Dependencies:** none. Standard library only (`net/http`, `encoding/json`, `iter`, `net/http/httptest`).
- **Tooling (via `go run`, not in go.mod):** staticcheck, govulncheck. Docker + docker compose for E2E.

# Architectural Directives
**API fidelity:** Struct fields and JSON tags match BOMHort exactly; timestamps stay strings as BOMHort sends them. Keep field doc comments with the BOMHort issue (`#350`) and the first release (`>= 0.7.0`) or *unreleased*. Never decode strictly by default — only `WithStrictDecoding()` (used by the integration tests) fails on unknown fields.

**Naming:** `ListX(ctx, *Opts)` = one page (`Paginated[T]`), `X(ctx, *Opts)` = `Seq[T]` iterator over all pages, `AllX` = collected slice. Option structs embed `ListOptions`; `nil` options mean server defaults. Path segments go through `esc` (`url.PathEscape`), queries through `url.Values`.

**VEX contract:** Statements are scoped to one SBOM (`?sbom_id=` or product resolution); a product without subcomponents is product-wide (`"*"`); matching is exact `(vuln_id, purl|"*")` with latest timestamp winning. Documented in `docs/VEX.md`, modelled by `bomhorttest`, verified by `TestVEX` in the integration suite. Never normalise PURLs or vuln ids in the client.

**Concurrency:** `Client`, `RateLimiter` and `bomhorttest.Server` are safe for concurrent use. Run `go test -race ./...` after touching them.

**Compatibility:** Additive changes only for BOMHort additions (new fields/methods). Unreleased BOMHort features are marked *unreleased* and integration-skipped on `404`. Breaking Go API changes need a CHANGELOG entry with migration notes.

**No git history rewrites on `main`.**

# Executable Commands

```
make check             # lint + test-race + build (what CI runs, minus E2E)
make lint              # gofmt check, go vet (incl. -tags=integration), staticcheck, tidy/no-deps check
make test / test-race  # unit + fake + example tests
make cover             # race tests + coverage.out + COVER_MIN gate (85 %)
make vuln              # govulncheck
make test-integration  # needs BOMHORT_URL (+ BOMHORT_API_KEY) of a live BOMHort with AUTH_ENABLED=true
make e2e               # ./hack/e2e-bomhort.sh — isolated BOMHort stack + integration tests (needs BOMHORT_SRC)
make e2e-ci            # same, building BOMHort images from $BOMHORT_SRC (what e2e.yml runs)
make clean
```

E2E variants:
```
BOMHORT_SRC=~/src/BOMHort BOMHORT_BUILD=1 ./hack/e2e-bomhort.sh
BOMHORT_SRC=~/src/BOMHort ./hack/e2e-bomhort.sh --keep -run TestVEX
docker compose -p bomhort-go-e2e -f hack/docker-compose.e2e.yml down -v
```

If `go` is not on PATH in your shell: `export PATH=$HOME/go/bin:$HOME/sdk/go<ver>/bin:$PATH GOTOOLCHAIN=local`.

# Code Style & Conventions

## Go
- Idiomatic Go, stdlib only. Errors are wrapped with context and the `bomhort:` prefix (`fmt.Errorf("bomhort: …: %w", err)`); HTTP failures are `*APIError`.
- Every exported identifier has a doc comment naming the endpoint (`GET /api/v1/…`).
- Unit tests use `httptest` servers or `bomhorttest`; never hit the network or a real BOMHort outside `test/integration`. Inject time (`c.sleep`) instead of sleeping in tests.
- Each new endpoint gets: method + doc comment, `endpoints_test.go` row, integration test call, `docs/API-COVERAGE.md` row, CHANGELOG entry. Runnable examples (`example_test.go`) for user-facing workflows.

## Git & PRs
- Commits are **DCO signed-off** (`git commit -s`). **Do not add `Co-authored-by` trailers** — project rules forbid them.
- Conventional, imperative subject lines (`Add …`, `Fix …`, `Keep …`); the body explains the why.
- PRs go to `seebom-labs/bomhort-go` `main` from a feature branch.
- **Releases:** tag `vX.Y.Z` after bumping `Version` in `bomhort.go` and the CHANGELOG (see `docs/RELEASING.md`); `release.yml` verifies both and publishes the GitHub release. Dependabot (actions, gomod) runs weekly.

# Boundaries
- **Always do:** Read the BOMHort source for the endpoint before adding or changing it. Write tests for all new behaviour. Keep `docs/API-COVERAGE.md`, `docs/VEX.md`, `docs/COMPATIBILITY.md`, README and CHANGELOG in sync. Run `make check` before pushing; run `make e2e` when anything that talks to BOMHort changes.
- **Workflow for every feature/fix:** (1) code, (2) tests (unit + `bomhorttest` + integration when BOMHort interaction changes), (3) docs + CHANGELOG, (4) `make check` green, (5) commit with `-s`, push branch. Open a PR only when asked.
- **Ask first:** Before adding any dependency, making a breaking change to the exported API, changing `bomhorttest` semantics away from BOMHort's, bumping the minimum Go version, changing the pinned BOMHort ref, or rewriting git history.
- **Never do:** Never commit secrets or real API keys (the only fixed key is the E2E dummy `bomhort-go-e2e-key`). Never normalise or rewrite PURLs/vuln ids. Never make strict decoding the default. Never add `Co-authored-by` trailers. Never force-push `main`.

# Security Posture
- Credentials come from the caller (`WithAPIKey`, `WithServiceToken`); the library never reads env vars or files and never logs credentials. `APIError` messages are truncated server text and never include request headers.
- Uploads reject source repo URLs with embedded credentials on the server side; the client passes them through unchanged and documents it — don't log `UploadOptions`.
- `DownloadSBOMTo` streams without buffering whole documents; responses are otherwise read fully (BOMHort bounds them). Keep `WithHTTPClient` timeouts sane (default 60 s).
- E2E stacks bind to `127.0.0.1` only and use dummy credentials.
