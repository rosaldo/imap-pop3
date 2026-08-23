# Changelog

> Generated from `git` by `scripts/gen-changelog.sh` — do not edit by hand.

- **v0.4.0** (2026-08-23) · `feat` — releases are built by CI on tag push, with push.sh only shipping commits and tag by default: Actions is free on public repositories, so the artefact no longer depends on whichever toolchain the workstation has — and --full keeps the local build as an escape hatch
- **v0.3.0** (2026-08-23) · `feat` — IMAP backend: resolve the upstream from the username's domain against a closed map, authenticate with the credentials received, and snapshot the mailbox at login
- **v0.2.0** (2026-08-23) · `feat` — POP3 AUTHORIZATION state: greeting, USER, PASS, CAPA, NOOP and QUIT over an injected listener, with a Shutdown that closes open sessions and an Accept loop that returns instead of spinning on a closed listener
- **v0.1.0** (2026-08-23) · `feat` — POP3-over-IMAP adapter scaffolding: module, MIT license, README, commit gate and CI running gofmt, vet, build and tests
