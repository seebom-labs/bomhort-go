# Testing

bomhort-go is tested at four levels. The first three run without network access or Docker.

| Level | Where | Command | Runs in CI |
|---|---|---|---|
| Unit / wire contract | `*_test.go` in the root package | `make test-race` | every push/PR (`ci.yml`) |
| Fake gateway | `bomhorttest/server_test.go` | `make test-race` | every push/PR |
| Examples | `example_test.go` (`// Output:` checked) | `make test` | every push/PR |
| Integration / E2E | `test/integration` (`-tags integration`) | `make test-integration` / `make e2e` | every push/PR against the pinned BOMHort, weekly also against BOMHort `main` (`e2e.yml`) |

## Unit tests

- `endpoints_test.go` is a table with one row per endpoint. Each row asserts method, escaped path, query string, headers, request body and the decoded response. Add a row for every new method.
- `client_test.go` covers auth headers, retries on 429 (`Retry-After` and back-off; the sleep function is injected), context cancellation, error decoding and strict decoding.
- `misc_test.go` covers upload validation, pagination helpers, `FindSBOM` and streaming downloads; `ratelimit_test.go` covers the limiter.

`make cover` enforces a minimum total coverage (`COVER_MIN`, default 85 %).

## The fake gateway (`bomhorttest`)

`bomhorttest.Server` is meant for **your** tests as well as ours. It models what a client can observe of BOMHort ≥ 0.7:

- auth: `X-API-Key`, `Authorization: Bearer`, `X-Service-Token`; public health probes; `403` for writes when auth is disabled;
- `/readyz` toggling (`SetReady`), pagination (default 50, max 500), `?search=` and `?project=`;
- SBOM reads incl. `detail` severity counts, `licenses`, `vex`, `download`; BOMHort's status codes for unknown/invalid ids;
- uploads: filename classification, parameter and header validation, SHA-256 duplicate detection, SBOM ingestion (`IngestUploads`) and VEX application (`ApplyUploads`) with BOMHort's scoping, product-wide and latest-wins rules ([VEX.md](VEX.md)), including late resolution when the SBOM arrives after its VEX;
- `PATCH` source attribution;
- `Handle(pattern, status, v)` for canned responses on all other routes; `Requests()` and `Snapshot()` for assertions.

Known simplifications: no OSV scanning (findings come from `AddSBOM`), product resolution does not consider `document_namespace`, aliases of findings are not modelled, and repository URL normalisation is simplified. The E2E suite exists to catch where the fake and the real thing diverge.

## Integration and E2E tests

`test/integration` runs against a live BOMHort:

```sh
BOMHORT_URL=http://localhost:18080 BOMHORT_API_KEY=... make test-integration
```

It needs `AUTH_ENABLED=true` (uploads), a writable SBOM directory and internet access for BOMHort's OSV scan. It

1. uploads `testdata/bomhort-0.6.1.spdx.json` (made unique per run) with project, cluster, namespace, tags and source attribution, and waits until BOMHort has parsed it and found vulnerabilities;
2. checks the SBOM, its detail, findings, dependencies, licenses, download (byte-identical) and lookups;
3. re-uploads the same bytes (duplicate), patches the source attribution;
4. uploads three OpenVEX documents — explicitly scoped with a subcomponent, scoped by product resolution, and product-wide — and waits until BOMHort applies each one exactly as documented;
5. calls every remaining endpoint.

All responses are decoded with `WithStrictDecoding()`. Endpoints marked *unreleased* are skipped when the server answers `404`. `BOMHORT_IT_TIMEOUT` (default `5m`) bounds each wait.

### Running BOMHort locally

`hack/e2e-bomhort.sh` starts an isolated stack (ClickHouse, api-gateway, ingestion-watcher, parsing-worker) with `hack/docker-compose.e2e.yml` on `localhost:18080` (API key `bomhort-go-e2e-key`), runs the integration tests and tears the stack down:

```sh
git clone https://github.com/seebom-labs/BOMHort ~/src/BOMHort
BOMHORT_SRC=~/src/BOMHort BOMHORT_BUILD=1 make e2e          # build images from the checkout
BOMHORT_SRC=~/src/BOMHort ./hack/e2e-bomhort.sh --keep -run TestVEX   # keep stack, one test
docker compose -p bomhort-go-e2e -f hack/docker-compose.e2e.yml down -v  # tear down a kept stack
```

Published images work too: `BOMHORT_IMAGE_PREFIX=ghcr.io/seebom-labs/bomhort/ BOMHORT_IMAGE_TAG=0.7.1`. On failure, compose logs are written to `.e2e/logs/`. SELinux hosts are handled (the bind mount is relabelled).

## API drift detection

BOMHort's API evolves on `main`. Drift shows up in three ways, all caught by `e2e.yml`:

| Drift | Detected by |
|---|---|
| New response field | strict decoding fails with `json: unknown field "…"` |
| Removed or renamed route | the call fails (`404`/`405`) |
| Changed semantics (e.g. VEX scoping) | integration assertions fail |

Pull requests run against `BOMHORT_PINNED_REF` (a release) so they stay green; the weekly schedule adds BOMHort `main`, and `workflow_dispatch` accepts any ref. When the `main` job fails: update `types.go`/methods (mark new things *unreleased*), `endpoints_test.go`, `bomhorttest` if behaviour changed, the integration test and [API-COVERAGE.md](API-COVERAGE.md).
