# Migrating from VEXViper's `internal/bomhort`

bomhort-go started as VEXViper's `internal/bomhort` package and its `bomhorttest` fake. It keeps the same shape (functional options, `APIError`, `UploadVEX(ctx, filename, doc, sbomID)`, sliding-window `RateLimiter`), but extends it to the full BOMHort API, which required a few breaking changes.

## Imports

```diff
-import "github.com/seebom-labs/vexviper/internal/bomhort"
-import "github.com/seebom-labs/vexviper/internal/bomhort/bomhorttest"
+import bomhort "github.com/seebom-labs/bomhort-go"
+import "github.com/seebom-labs/bomhort-go/bomhorttest"
```

## Client

| VEXViper | bomhort-go | Notes |
|---|---|---|
| `ListSBOMs(ctx, page, pageSize, search)` | `ListSBOMs(ctx, &bomhort.SBOMListOptions{ListOptions: bomhort.ListOptions{Page: page, PageSize: pageSize}, Search: search})` | options struct; `nil` = server defaults |
| `AllSBOMs(ctx)` | `AllSBOMs(ctx, nil)` | or iterate lazily with `SBOMs(ctx, nil)` |
| `VEXStatements(ctx, page, pageSize)` (one page) | `ListVEXStatements(ctx, &bomhort.ListOptions{Page: page, PageSize: pageSize})` | `VEXStatements` is now the iterator |
| `AllVEXStatements(ctx)` | unchanged | |
| `FindSBOM(ctx, ref)` | unchanged | now also matches uploaded filenames (`pushed/<uuid>-<name>`) and uses `?search=` first |
| `Healthy`, `Vulnerabilities`, `Dependencies`, `DownloadSBOM`, `UploadVEX`, `BaseURL` | unchanged | |
| `WithAPIKey`, `WithServiceToken`, `WithHTTPClient`, `WithRateLimit`, `WithMaxRetries` | unchanged | new: `WithRateLimiter`, `WithUserAgent`, `WithStrictDecoding` |
| `IsNotFound(err)` | unchanged | new: `IsBadRequest`, `IsUnauthorized`, `IsForbidden`, `IsRateLimited`, `IsUnavailable`, `StatusCode` |

Behaviour changes:

- `APIError` gained `Method` and `Path`; `Error()` now reads `bomhort: GET /api/v1/…: HTTP 404: …`. Match on `IsNotFound`/`StatusCode`, not on the string.
- `New` also strips a trailing `/api/v1` from the base URL.
- Requests carry `User-Agent: bomhort-go/<version>`.
- Types gained fields (`SBOM.Cluster/Namespace/Project/DocumentVersion`, `UploadResult.Namespace/Project/Parent/Message`, …). Struct literals with positional fields would break; keyed literals do not.

New API you can now use instead of hand-rolled HTTP: `SBOMDetail`, `SBOMLicenses`, `SBOMVEXStatements`, `DownloadSBOMTo` (streaming), `UploadSBOM` / `Upload` with ownership, tags and source attribution, `PatchSBOMSource`, `ListVulnerabilities`, `AffectedProjects`, projects/tags/clusters/namespaces/fleet, statistics, search, package and license endpoints — see [API-COVERAGE.md](API-COVERAGE.md).

## `bomhorttest`

The fake is now a faithful model of BOMHort ≥ 0.7 rather than a minimal stub.

| VEXViper | bomhort-go |
|---|---|
| exported fields `SBOMs`, `Vulns`, `Deps`, `Raw`, `Uploads`, `Statements` | unexported; use `AddSBOM`, `SetLicenses`, `AddStatement`, `SBOMs()`, `Snapshot()`, `Requests()` |
| `AddSBOM(...)` returned nothing | returns the stored `SBOM` (empty `ID` → random UUID, `VulnCount` derived) |
| unknown SBOM id → `404` on per-SBOM lists | `200 []` like BOMHort; non-UUID ids → `400`; `detail`/`download` → `404` |
| auth disabled (`New("")`) allowed uploads | uploads and `PATCH` answer `403` like BOMHort with `AUTH_ENABLED=false` |
| unscoped uploads applied globally by `(vuln_id, purl)` | statements are scoped: `?sbom_id=` or product resolution (id, source repo, document name); unresolved statements apply nowhere |
| `products[].@id` always used as the match purl | spec shape: `subcomponents` purls; product without subcomponents → product-wide `"*"` once scoped |
| `ApplyUploads` | unchanged; new `IngestUploads` registers uploaded SBOMs |

Also new: all health probes, `SetReady(false)` for `/readyz` `503`, `?search=`/`?project=` filters, `detail`, `licenses`, `vex`, `PATCH`, duplicate detection by SHA-256, header and parameter validation, `Handle(pattern, status, v)` for canned responses on any other route, `UUID(n)` for deterministic fixture ids.

## A note for VEXViper's VEX shape

VEXViper writes statements whose product `@id` is the finding's purl and uploads them with `?sbom_id=`. BOMHort ≥ 0.7 treats a product without `subcomponents` under an explicit `sbom_id` as **product-wide** (`product_purl = "*"`): the statement then covers every package in that SBOM with the same vulnerability ID, not only the purl it was written for. Usually that's harmless (one vulnerability ID, one package), but for an exact, per-package verdict use the spec shape — product = the SBOM/repo, `subcomponents` = the purl. See [VEX.md](VEX.md).
