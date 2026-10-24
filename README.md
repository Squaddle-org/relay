# Squaddle Relay

Content-blind relay for [Squaddle](https://github.com/squaddle-org/spec): stores signed membership logs and
encrypted ops, enforces access and invite rules, fans out updates, sends content-free push wake-ups.
Single Go binary + SQLite. Self-hosted relays run without limits by default.

```bash
make run                          # dev server on :8080, metrics/health on :9090
make test                         # fetches spec test vectors (SPEC_VERSION) and runs tests
SQUADDLE_SPEC_DIR=../spec make test
docker run -v relay-data:/data -p 8080:8080 ghcr.io/squaddle-org/relay:latest
```
Kubernetes: `deploy/k8s` is a Kustomize base (`kubectl apply -k deploy/k8s` or reference it remotely from Flux).
