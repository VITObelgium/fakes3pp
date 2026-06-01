# AGENTS.md

## Setup
- Local proxy commands expect `etc.private` to exist. Bootstrap from `etc/` and update `etc.private/.env.docker` plus the referenced config files.
- `make build-container` builds the single image used by both proxy entrypoints.
- Optional: set `FAKES3PP_ROLE_TRUST_POLICY_PATH` to enable trust-policy enforcement for `AssumeRoleWithWebIdentity`. Files live in a separate directory from `FAKES3PP_ROLE_POLICY_PATH`, use the same `<base32(arn)>.json.tmpl` naming, and are hot-reloaded via fsnotify. When unset (or when no file exists for a given role) the call is allowed (default-allow). See `etc/trust-policies/README.md`.

## Entrypoints
- The CLI binary is `fakes3pp` from `main.go`; the main server subcommands are `proxys3` and `proxysts` in `cmd/`.
- Both proxy commands load env from the `--dot-env` flag in `cmd/root.go`; the make targets pass `--dot-env /etc/fakes3pp/.env.docker` inside the container.
- Config is env-driven through Viper with `FAKES3PP_` variables; `cmd/config.go` is the source of truth for required settings.

## Run
- S3 proxy: `make run-container-s3`
- STS proxy: `make run-container-sts`
- Both targets bind-mount `./etc.private` into the container and expose metrics on host port `5555` for S3 and `5556` for STS.

## Tests
- Moto-backed tests require a Python venv: `make setup-test-dependencies`.
- Start the fake S3 backends before integration-style tests: `make start-test-s3-servers`. This boots two moto servers on `localhost:5000` and `localhost:5001` and seeds them via `testing/bootstrap_backend.py`.
- Stop them with `make stop-test-s3-servers` when done.
- CI runs tests as `go clean -testcache && go test -p 1 -coverprofile cover.out -v ./...`. Keep `-p 1` when reproducing full-suite runs because tests share fixed ports.
- Slow tests are gated by `HASTE_MAKES_WASTE`; set it when you intentionally want the slow unit tests.

## Verification
- CI covers `golangci-lint`, `go build -v ./...`, and the serialized Go test command above.
- Pre-commit also runs `go-mod-tidy`, `go-vet`, `gosec`, `staticcheck`, `go fmt`, secret scanning, and YAML/file hygiene hooks via `.pre-commit-config.yaml`.

## Benchmarks
- `make bench-main` is not worktree-safe: it fetches `origin`, creates a local `before_going_to_main` branch, checks out `origin/main`, and writes benchmark artifacts into `cmd/`.
- Benchmark flow is `make bench-main`, `make bench-current`, then `make bench-report`.

## Release / CI Gotchas
- Helm releases are tag-driven: `chart-v*` tags must match `charts/fakes3pp/Chart.yaml` version exactly.
- Container release tags are `v*`; the workflow strips the leading `v` before pushing to `ghcr.io`.
