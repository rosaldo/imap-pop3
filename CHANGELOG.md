# Changelog

> Generated from `git` by `scripts/gen-changelog.sh` — do not edit by hand.

- **v0.8.0** (2026-08-23) · `feat` — configuration file and TLS-only boot: the server reads its upstream map from YAML and refuses to start without a certificate that loads, with an empty upstream map, or on a misspelled key — a mail password must never be downgraded to the clear because a path was wrong
- **v0.7.0** (2026-08-23) · `feat` — DELE marks and QUIT executes: deletions are held in the session and only flagged and expunged in the UPDATE state, so a connection that drops mid-session removes nothing, RSET clears the marks, and a failed removal is reported as -ERR instead of being swallowed
- **v0.6.0** (2026-08-23) · `feat` — UIDL pairs UIDVALIDITY with the IMAP UID: the UID alone is unique only within one mailbox incarnation, so a recreated mailbox would recycle identifiers a client had already stored and make it skip mail or download it twice
- **v0.5.0** (2026-08-23) · `feat` — STAT, LIST, RETR and TOP, streamed and dot-encoded: bodies are copied straight from the IMAP literal to the wire instead of being held in memory, and net/textproto does the stuffing that keeps a line starting with a dot from ending the transfer early
- **v0.4.0** (2026-08-23) · `feat` — releases are built by CI on tag push, with push.sh only shipping commits and tag by default: Actions is free on public repositories, so the artefact no longer depends on whichever toolchain the workstation has — and --full keeps the local build as an escape hatch
- **v0.3.0** (2026-08-23) · `feat` — IMAP backend: resolve the upstream from the username's domain against a closed map, authenticate with the credentials received, and snapshot the mailbox at login
- **v0.2.0** (2026-08-23) · `feat` — POP3 AUTHORIZATION state: greeting, USER, PASS, CAPA, NOOP and QUIT over an injected listener, with a Shutdown that closes open sessions and an Accept loop that returns instead of spinning on a closed listener
- **v0.1.0** (2026-08-23) · `feat` — POP3-over-IMAP adapter scaffolding: module, MIT license, README, commit gate and CI running gofmt, vet, build and tests
