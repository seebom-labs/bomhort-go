# API coverage

Every route of the BOMHort api-gateway (`backend/cmd/api-gateway/main.go`) and the client method that calls it.

**Since** is the first BOMHort release with the route (≤ 0.6 = present in 0.6.1, the oldest release checked); *unreleased* means it is on BOMHort `main` but not in a release yet (older servers answer `404`). Pagination column: ✓ = `ListX` page call + `X` iterator (+ `AllX` where useful).

All `/api/v1` routes require authentication when BOMHort runs with `AUTH_ENABLED=true`; the health probes are always public.

## Health

| Method & path | Client | Returns | Since |
|---|---|---|---|
| `GET /healthz` | `Healthy` | `error` | ≤ 0.6 |
| `GET /livez` | `Live` | `error` | ≤ 0.6 |
| `GET /readyz` | `Ready` | `error` (`503` → `IsUnavailable`) | ≤ 0.6 |

## SBOMs

| Method & path | Client | Returns | Paginated | Since |
|---|---|---|---|---|
| `GET /api/v1/sboms` | `ListSBOMs`, `SBOMs`, `AllSBOMs`, `FindSBOM` | `SBOM` | ✓ | ≤ 0.6 |
| ↳ `?search=` | `SBOMListOptions.Search` | | | ≤ 0.6 |
| ↳ `?project=` | `SBOMListOptions.Project` | | | unreleased (ignored by older servers) |
| `GET /api/v1/sboms/{id}/detail` | `SBOMDetail` | `SBOMDetail` | | ≤ 0.6 |
| `GET /api/v1/sboms/{id}/vulnerabilities` | `Vulnerabilities` | `[]Vulnerability` | | ≤ 0.6 |
| `GET /api/v1/sboms/{id}/dependencies` | `Dependencies` | `[]DependencyNode` | | ≤ 0.6 |
| `GET /api/v1/sboms/{id}/licenses` | `SBOMLicenses` | `[]SBOMLicense` | | ≤ 0.6 |
| `GET /api/v1/sboms/{id}/vex` | `SBOMVEXStatements` | `[]VEXStatement` | | 0.7.0 |
| `GET /api/v1/sboms/{id}/download` | `DownloadSBOM`, `DownloadSBOMTo` | `[]byte` / streamed | | ≤ 0.6 |
| `PATCH /api/v1/sboms/{id}` | `PatchSBOMSource` | `SourceAttribution` | | 0.7.0 |
| `POST /api/v1/sboms/upload` | `Upload`, `UploadSBOM`, `UploadVEX` | `UploadResult` | | 0.7.0 |
| ↳ `?sbom_id=` (VEX only) | `UploadOptions.SBOMID` | | | 0.7.0 |
| ↳ `?cluster= ?namespace= ?project= ?tags=` | `UploadOptions` | | | 0.7.0 |
| ↳ `?parent=` | `UploadOptions.Parent` | `UploadResult.Parent` | | unreleased |
| ↳ `X-Source-Repo`, `X-Source-Ref` | `UploadOptions.SourceRepo/SourceRef` | | | 0.7.0 |

Per-SBOM lists answer `200 []` for unknown (but well-formed) ids and `400` for ids that are not UUIDs; `detail` and `download` answer `404`.

## Vulnerabilities & VEX

| Method & path | Client | Returns | Paginated | Since |
|---|---|---|---|---|
| `GET /api/v1/vulnerabilities` | `ListVulnerabilities` | `Vulnerability` | ✓ | ≤ 0.6 |
| `GET /api/v1/vulnerabilities/{id}/affected-projects` | `AffectedProjects` | `[]AffectedProject` | | ≤ 0.6 |
| `GET /api/v1/vex/statements` | `ListVEXStatements`, `VEXStatements`, `AllVEXStatements` | `VEXStatement` | ✓ | ≤ 0.6 |

## Projects, tags, ownership

| Method & path | Client | Returns | Paginated | Since |
|---|---|---|---|---|
| `GET /api/v1/projects` | `ListProjects`, `Projects` | `Project` | ✓ | ≤ 0.6 |
| ↳ `?search=` / `?tag=` | `ProjectListOptions.Search` / `.Tag` | | | ≤ 0.6 / 0.7.0 |
| ↳ `?group_by=parent` | `ListProjectGroups` | `ProjectGroup` | ✓ | unreleased (older servers ignore it and return projects) |
| `GET /api/v1/projects/{name}` | `Project` | `ProjectDetail` | | unreleased |
| `GET /api/v1/projects/{name}/sboms` | `ListProjectSBOMs` | `SBOM` | ✓ | unreleased |
| `GET /api/v1/projects/{name}/vulnerabilities` | `ProjectVulnerabilities` | `[]Vulnerability` (with `AffectedSBOMs`) | | unreleased |
| `GET /api/v1/projects/{name}/packages` | `ListProjectPackages` | `ProjectPackage` | ✓ | unreleased |
| `GET /api/v1/projects/license-compliance` | `LicenseViolations` | `[]LicenseViolation` | | ≤ 0.6 |
| `GET /api/v1/tags` | `Tags` | `[]Tag` | | 0.7.0 |
| `GET /api/v1/clusters` | `Clusters` | `[]Cluster` | | ≤ 0.6 |
| `GET /api/v1/clusters/{name}/stats` | `ClusterStats` | `ClusterStats` | | ≤ 0.6 |
| `GET /api/v1/clusters/{name}/sboms` | `ListClusterSBOMs` | `SBOM` | ✓ | ≤ 0.6 |
| `GET /api/v1/namespaces` (`?cluster=`) | `Namespaces` | `[]Namespace` | | 0.7.0 |
| `GET /api/v1/namespaces/{name}/stats` | `NamespaceStats` | `NamespaceStats` | | 0.7.0 |
| `GET /api/v1/namespaces/{name}/sboms` | `ListNamespaceSBOMs` | `SBOM` | ✓ | 0.7.0 |
| `GET /api/v1/fleet` | `Fleet` | `[]FleetCluster` | | 0.7.0 |

Project names may contain `/` (`argo/cd`); the client percent-encodes path segments. A project literally named `license-compliance` cannot be fetched via `/projects/{name}` because the static route wins on the server.

## Statistics, search, packages, licenses

| Method & path | Client | Returns | Since |
|---|---|---|---|
| `GET /api/v1/stats/dashboard` | `DashboardStats` | `DashboardStats` | ≤ 0.6 |
| `GET /api/v1/stats/dependencies` (`?limit=`) | `DependencyStats` | `DependencyStats` | ≤ 0.6 |
| `GET /api/v1/stats/version-skew` | `VersionSkew` | `VersionSkew` (paginated body) | ≤ 0.6 |
| `GET /api/v1/search` (`?q= &limit=`) | `Search` | `SearchResult` | ≤ 0.6 |
| `GET /api/v1/packages/search` | `SearchPackages` | `PackageSearch` | ≤ 0.6 |
| `GET /api/v1/packages/detail` (`?name=`) | `PackageDetail` | `PackageDetail` | ≤ 0.6 |
| `GET /api/v1/packages/archived` | `ArchivedPackages` | `[]ArchivedPackage` | ≤ 0.6 |
| `GET /api/v1/licenses/compliance` | `LicenseCompliance` | `[]LicenseCompliance` | ≤ 0.6 |
| `GET /api/v1/license-exceptions` | `LicenseExceptions` | `LicenseExceptions` | ≤ 0.6 |
| `GET /api/v1/license-policy` | `LicensePolicy` | `LicensePolicy` | ≤ 0.6 |

## How coverage is verified

- `endpoints_test.go` pins method, escaped path, query, headers, body and response decoding of every row above against an `httptest` server.
- `test/integration` calls every row against a real BOMHort with `WithStrictDecoding()`; rows marked *unreleased* are skipped on released servers. CI runs it against the pinned release on every PR and against BOMHort `main` weekly ([TESTING.md](TESTING.md)).

When BOMHort adds a route or a field: add the method/field here, in `types.go` (mark it *unreleased* until it ships), in `endpoints_test.go` and in the integration tests.
