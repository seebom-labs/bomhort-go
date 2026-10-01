# Releasing

Releases are tags `vX.Y.Z` on `main` (pre-releases `vX.Y.Z-rc.N`). `.github/workflows/release.yml` does the rest.

## Checklist

1. Make sure `main` is green (CI and E2E against the pinned BOMHort). For releases that add support for a new BOMHort version, bump `BOMHORT_PINNED_REF` in `.github/workflows/e2e.yml` and [COMPATIBILITY.md](COMPATIBILITY.md) first.
2. In one commit (`git commit -s -m "Release vX.Y.Z"`):
   - set `const Version = "X.Y.Z"` in `bomhort.go`;
   - move the `## [Unreleased]` entries of `CHANGELOG.md` under `## [X.Y.Z] - YYYY-MM-DD`;
   - drop *unreleased* markers for BOMHort features that shipped in the meantime (types, methods, API-COVERAGE.md, COMPATIBILITY.md).
3. Tag and push:
   ```sh
   git tag -s vX.Y.Z -m vX.Y.Z   # or -a if you don't sign tags
   git push origin main vX.Y.Z
   ```
4. The workflow re-runs `make check`, verifies that the tag matches `bomhort.Version` and that `CHANGELOG.md` has a section for it, creates the GitHub release with that section as notes (tags with `-` become pre-releases) and asks `proxy.golang.org` to fetch the version.
5. Afterwards set `Version` to the next `-dev` version (e.g. `X.Y+1.0-dev`) and add an empty `## [Unreleased]` section.

## Module path

The module path is `github.com/seebom-labs/bomhort-go`. The proxy step only runs in that repository; in forks the release is created but `go get` will not resolve it.

## Versioning

See [COMPATIBILITY.md](COMPATIBILITY.md#versioning-policy). In short: semver; while on 0.x, minor versions may contain breaking changes, which must be called out in the changelog with migration notes.
