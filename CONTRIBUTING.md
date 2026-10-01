# Contributing

Thanks for helping! bomhort-go is a small, dependency-free library, and we want to keep it that way.

## Ground rules

- **Stdlib only.** No third-party modules in `go.mod` (`make tidy-check` enforces it). Test tooling runs via `go run …@version` in the Makefile.
- **Follow BOMHort, don't invent.** Types and behaviour mirror the BOMHort api-gateway source (`backend/cmd/api-gateway`, `backend/pkg/dto`). Link the BOMHort issue/PR when you add something.
- **Everything is tested.** New endpoint → method + `endpoints_test.go` row + integration test + [docs/API-COVERAGE.md](docs/API-COVERAGE.md). New behaviour in BOMHort that clients observe → model it in `bomhorttest` with tests.
- **Mark unreleased API.** Features that only exist on BOMHort `main` are marked *unreleased* in doc comments and docs, and the integration test skips them on `404`.

## Workflow

```sh
make check              # gofmt, vet (incl. integration tag), staticcheck, no-deps, race tests, build
make cover              # coverage gate
BOMHORT_SRC=~/src/BOMHort BOMHORT_BUILD=1 make e2e   # when you touch anything that talks to BOMHort
```

1. Fork, create a feature branch.
2. Make the change with tests and docs; update `CHANGELOG.md` under `[Unreleased]`.
3. Commit with a DCO sign-off: `git commit -s`. Imperative subject (`Add …`, `Fix …`), body explains why.
4. Open a PR against `main`. CI and the E2E job against the pinned BOMHort release must be green.

## Developer Certificate of Origin

All commits must be signed off (`Signed-off-by: Name <email>`), certifying the [DCO](https://developercertificate.org/). `git commit -s` adds it.

## Reporting bugs

Please include the bomhort-go version, the BOMHort version (`/healthz`, image tag or commit) and, if possible, a failing test using `bomhorttest` or the request/response pair.
