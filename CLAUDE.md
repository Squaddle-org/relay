# CLAUDE.md — relay repo

Go relay for Squaddle. The spec lives in `../spec` (sibling checkout). **Read `../spec/protocol/PROTOCOL.md`,
`../spec/protocol/relay-api.yaml` and `../spec/ROADMAP.md` (milestone M2) before coding.** The spec wins.

## Hard rules
- The relay never decrypts content and never needs to. A feature that would → stop, propose an ADR in `../spec`.
- `internal/membership` implements exactly PROTOCOL.md §3.3 and must pass the spec test vectors
  (`logentry.json`, `log-reject.json`). Same rules as `../core` membership.
- Verify every signature with domain separation (PROTOCOL.md §1). Request auth per §5, replay cache, 60s window.
- Limits are relay policy (§8): default `-limits=none`; downgrades never delete members or content.
- Never log request bodies, auth headers, invite ids with secrets, or push endpoints. Metrics without room ids as labels.
- Dependencies: stdlib first. Allowed: `modernc.org/sqlite`, `github.com/fxamacker/cbor/v2`, `golang.org/x/crypto`,
  `github.com/coder/websocket`, `github.com/prometheus/client_golang`. Anything else → ask.
- After a spec release: bump `SPEC_VERSION`, `make test`.

## Commands
```bash
make lint test
SQUADDLE_SPEC_DIR=../spec make test
make run
```
