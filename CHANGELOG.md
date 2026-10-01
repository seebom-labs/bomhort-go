# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [semantic versioning](https://semver.org) (see [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md)).

## [Unreleased]

Initial version, extracted from [VEXViper](https://github.com/seebom-labs/VEXViper)'s `internal/bomhort` and extended to the complete BOMHort API.

### Added

- Client for every public BOMHort api-gateway route: health probes; SBOM listing, lookup, detail, findings, dependencies, licenses, VEX statements, download (buffered and streaming); uploads of SBOM and VEX documents with ownership, tags, parent and source attribution; source-attribution `PATCH`; fleet-wide vulnerabilities, VEX statements and affected projects; projects (incl. unreleased detail, SBOMs, vulnerabilities, packages, parent groups), tags, clusters, namespaces, fleet; dashboard, dependency and version-skew statistics; search, package search/detail, archived packages; license compliance, violations, exceptions and policy.
- Typed errors (`APIError`, `IsNotFound`, `IsBadRequest`, `IsUnauthorized`, `IsForbidden`, `IsRateLimited`, `IsUnavailable`, `StatusCode`).
- Iterator-based pagination (`ListX` / `X` / `AllX`, `Paginate`, `Collect`).
- Options: API key, service token, HTTP client, user agent, rate limit / shared `RateLimiter`, 429 retries, strict decoding.
- `bomhorttest`: in-memory fake gateway modelling BOMHort ≥ 0.7 auth, pagination, uploads, duplicate detection, VEX scoping/product-wide/latest-wins matching and source `PATCH`, with canned responses for all other routes.
- Integration tests against a real BOMHort with strict decoding, docker-compose E2E harness, CI (lint, staticcheck, race tests on min/latest Go, coverage gate, govulncheck), weekly API-drift job against BOMHort `main`, release workflow.
- Documentation: API coverage, VEX contract, compatibility, testing, migration from VEXViper, releasing, contributing, AGENTS.md.

[Unreleased]: https://github.com/seebom-labs/bomhort-go/commits/main
