# bomhort-go

[![CI](https://github.com/seebom-labs/bomhort-go/actions/workflows/ci.yml/badge.svg)](https://github.com/seebom-labs/bomhort-go/actions/workflows/ci.yml)
[![E2E](https://github.com/seebom-labs/bomhort-go/actions/workflows/e2e.yml/badge.svg)](https://github.com/seebom-labs/bomhort-go/actions/workflows/e2e.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/seebom-labs/bomhort-go.svg)](https://pkg.go.dev/github.com/seebom-labs/bomhort-go)

The Go client for the [BOMHort](https://github.com/seebom-labs/BOMHort) REST API.

- **Complete:** every public endpoint of the BOMHort api-gateway — SBOMs, findings, dependency trees, licenses, VEX, projects, clusters, namespaces, fleet, statistics, search, push-model uploads and source attribution ([coverage](docs/API-COVERAGE.md)).
- **Zero dependencies:** standard library only.
- **Production behaviour built in:** API key / service token auth, client-side rate limiting, 429 retries honouring `Retry-After`, typed errors, iterator-based pagination, streaming downloads.
- **Testable:** [`bomhorttest`](bomhorttest) is an in-memory fake gateway with BOMHort's real upload, VEX scoping and matching semantics.
- **Verified against real BOMHort:** every PR runs the integration suite with strict decoding against a pinned BOMHort release; a weekly job also runs it against BOMHort `main` to catch API drift.

Extracted from [VEXViper](https://github.com/seebom-labs/VEXViper)'s `internal/bomhort` ([why](https://github.com/seebom-labs/VEXViper/blob/main/docs/INTEGRATION.md#8-should-the-bomhort-go-client-be-its-own-module)).

## Install

```sh
go get github.com/seebom-labs/bomhort-go
```

Requires Go 1.25+. See [compatibility](docs/COMPATIBILITY.md) for supported BOMHort versions.

## Quick start

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	bomhort "github.com/seebom-labs/bomhort-go"
)

func main() {
	c := bomhort.New("https://bomhort.example.com",
		bomhort.WithAPIKey(os.Getenv("BOMHORT_API_KEY")),
		bomhort.WithRateLimit(90, 10*time.Second), // BOMHort allows 100 req / 10 s per IP
	)
	ctx := context.Background()

	for sbom, err := range c.SBOMs(ctx, nil) {
		if err != nil {
			log.Fatal(err)
		}
		vulns, err := c.Vulnerabilities(ctx, sbom.ID)
		if err != nil {
			log.Fatal(err)
		}
		for _, v := range vulns {
			fmt.Printf("%s\t%s\t%s\t%s\n", sbom.DocumentName, v.Severity, v.VulnID, v.PURL)
		}
	}
}
```

More runnable examples are in [`example_test.go`](example_test.go) and on [pkg.go.dev](https://pkg.go.dev/github.com/seebom-labs/bomhort-go).

## Usage

### Client options

| Option | Purpose |
|--------|---------|
| `WithAPIKey(key)` | Sends `X-API-Key` (BOMHort `API_KEYS`) |
| `WithServiceToken(tok)` | Sends `Authorization: Bearer` (BOMHort `SERVICE_TOKEN`) |
| `WithRateLimit(n, window)` / `WithRateLimiter(rl)` | Client-side pacing; share one `RateLimiter` between clients that hit the same instance |
| `WithMaxRetries(n)` | Retries on HTTP 429 (default 3); honours `Retry-After`, else exponential back-off |
| `WithHTTPClient(hc)` | Custom transport, proxy, TLS, timeout (default timeout 60 s) |
| `WithUserAgent(ua)` | Default `bomhort-go/<version>` |
| `WithStrictDecoding()` | Fail on JSON fields the client does not know — for contract tests, not production |

`New` accepts the instance root, with or without a trailing `/api/v1`.

### Pagination

Paginated endpoints come in three flavours:

| Form | Example | Returns |
|------|---------|---------|
| `ListX` | `ListSBOMs(ctx, opts)` | one page: `Paginated[T]{Data, Total, Page, PageSize}` |
| `X` | `SBOMs(ctx, opts)` | lazy `iter.Seq2[T, error]` over all pages |
| `AllX` | `AllSBOMs(ctx, opts)` | every item as a slice |

`bomhort.Paginate` turns any `List*` call into an iterator, `bomhort.Collect` drains one.

### Errors

Non-2xx responses are `*bomhort.APIError` (status, server message, method, path):

```go
d, err := c.SBOMDetail(ctx, id)
switch {
case bomhort.IsNotFound(err):     // 404
case bomhort.IsUnauthorized(err): // 401: missing/invalid key
case bomhort.IsForbidden(err):    // 403: e.g. upload with AUTH_ENABLED=false
case bomhort.IsRateLimited(err):  // 429 after all retries
case bomhort.IsUnavailable(err):  // 503: storage / ClickHouse down
case err != nil:                  // transport error, decode error, ...
}
```

### Uploading SBOMs and VEX

```go
res, err := c.UploadSBOM(ctx, "checkout.spdx.json", doc, &bomhort.UploadOptions{
	Project:    "checkout",
	Tags:       []string{"payments"},
	SourceRepo: "https://github.com/example/checkout",
	SourceRef:  "v1.4.0",
})
// res.Status == "pending" (job enqueued) or res.Duplicate() == true

res, err = c.UploadVEX(ctx, "checkout.openvex.json", vexDoc, sbom.ID) // scoped to one SBOM
```

Uploads require `AUTH_ENABLED=true` on the BOMHort side. Ingestion is asynchronous — poll the SBOM or its findings until the result shows up.

**Read [docs/VEX.md](docs/VEX.md) before writing VEX for BOMHort.** It documents exactly how BOMHort scopes statements to SBOMs and matches them to findings; getting the product/subcomponent shape wrong silently suppresses nothing (or more than intended).

### Testing your code

```go
srv := bomhorttest.New("test-key")
defer srv.Close()
sbom := srv.AddSBOM(bomhort.SBOM{DocumentName: "app"}, []bomhort.Vulnerability{
	{VulnID: "GHSA-xxxx", Severity: "HIGH", PURL: "pkg:golang/golang.org/x/net@v0.17.0"},
}, nil, nil)
srv.Handle("GET /api/v1/fleet", 200, []bomhort.FleetCluster{{Name: "prod"}}) // canned response

c := bomhort.New(srv.URL, bomhort.WithAPIKey("test-key"))
// ... exercise your code, then inspect srv.Snapshot() / srv.Requests()
```

The fake implements health probes, auth, pagination and filters, SBOM reads, downloads, uploads (ingesting SBOMs, applying VEX with BOMHort's scoping and matching rules), duplicate detection and the source PATCH. Any other endpoint can be served with `Handle`. See [docs/TESTING.md](docs/TESTING.md).

## Documentation

| Document | Contents |
|----------|----------|
| [docs/API-COVERAGE.md](docs/API-COVERAGE.md) | Every BOMHort endpoint ↔ client method ↔ type, with the BOMHort version it appeared in |
| [docs/VEX.md](docs/VEX.md) | Upload contract, VEX scoping, product-wide statements and the matching rules |
| [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) | Supported Go and BOMHort versions, versioning policy, unreleased endpoints |
| [docs/TESTING.md](docs/TESTING.md) | Unit tests, the fake server, integration and E2E tests, API drift detection |
| [docs/MIGRATING-FROM-VEXVIPER.md](docs/MIGRATING-FROM-VEXVIPER.md) | Moving from VEXViper's `internal/bomhort` |
| [docs/RELEASING.md](docs/RELEASING.md) | Release process |
| [CONTRIBUTING.md](CONTRIBUTING.md) · [AGENTS.md](AGENTS.md) | How to contribute (humans and coding agents) |
| [CHANGELOG.md](CHANGELOG.md) | Release notes |

## Development

```sh
make check            # lint (gofmt, vet, staticcheck, no-deps) + race tests + build
make cover            # tests with coverage gate
BOMHORT_SRC=~/src/BOMHort BOMHORT_BUILD=1 make e2e   # real BOMHort via docker compose
```

## License

[Apache-2.0](LICENSE)
