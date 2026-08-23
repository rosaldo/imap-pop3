# Changelog

> Generated from `git` by `scripts/gen-changelog.sh` — do not edit by hand.

- **v0.3.0** (2026-08-23) · `feat` — IMAP backend: resolve the upstream from the username's domain against a closed map, authenticate with the credentials received, and snapshot the mailbox at login
- **v0.2.0** (2026-08-23) · `feat` — POP3 AUTHORIZATION state: greeting, USER, PASS, CAPA, NOOP and QUIT over an injected listener, with a Shutdown that closes open sessions and an Accept loop that returns instead of spinning on a closed listener
- **v0.1.0** (2026-08-23) · `feat` — POP3-over-IMAP adapter scaffolding: module, MIT license, README, commit gate and CI running gofmt, vet, build and tests
