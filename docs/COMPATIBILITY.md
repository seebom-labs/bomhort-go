# Compatibility & versioning

## Supported versions

| bomhort-go | Go | BOMHort (tested in CI) | Notes |
|---|---|---|---|
| `main` / 0.1.x | 1.25+ (`go.mod`) and latest stable | **0.7.1** (pinned, every PR) · **`main`** (weekly) | Works with 0.6.x for read endpoints; uploads, `PATCH` and VEX scoping need ≥ 0.7.0 |

The pinned BOMHort ref lives in `.github/workflows/e2e.yml` (`BOMHORT_PINNED_REF`). Bump it — and this table — when a new BOMHort release ships.

## Unreleased BOMHort API

The client already covers endpoints and fields that are on BOMHort `main` but not yet released. On released servers they behave as follows:

| Feature | On BOMHort 0.7.1 |
|---|---|
| `Project`, `ListProjectSBOMs`, `ProjectVulnerabilities`, `ListProjectPackages` | `404` → `IsNotFound(err)` |
| `ListProjectGroups` (`?group_by=parent`) | parameter ignored; the server returns plain projects, which decode into mostly-empty `ProjectGroup`s (and fail with `WithStrictDecoding`) |
| `SBOMListOptions.Project` (`?project=`) | ignored: all SBOMs are returned |
| `UploadOptions.Parent` (`?parent=`) | ignored |
| `Project.Parent`, `Project.ParentSource`, `Tag.IsProject`, `Vulnerability.AffectedSBOMs`, `UploadResult.Parent` | empty |

These are marked *unreleased* in the Go doc comments and in [API-COVERAGE.md](API-COVERAGE.md).

## Versioning policy

bomhort-go follows [semantic versioning](https://semver.org) for its Go API.

- **0.x:** the API may still change between minor versions; every change is listed in [CHANGELOG.md](../CHANGELOG.md) with migration notes.
- **1.x (planned once BOMHort's API stabilises):** no breaking changes to exported identifiers within a major version.
- New BOMHort fields are added as new struct fields (not breaking). Removed or renamed BOMHort fields are kept as deprecated fields for at least one minor release.
- The client never decodes strictly by default, so a newer BOMHort that adds fields does not break an older client.
- `bomhorttest` is part of the public API and versioned with it; its behaviour tracks the BOMHort release pinned in CI.

## Go version policy

The `go` directive in `go.mod` is the minimum supported version; CI tests it and the latest stable release. The minimum is raised only when a needed language or stdlib feature requires it (currently range-over-func iterators and `iter.Seq2`, Go 1.23+, and the toolchain in use).
