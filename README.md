# imap-pop3

Serve an IMAP mailbox over POP3. For clients that only speak POP3 and servers that only speak
IMAP.

```sh
imap-pop3 --config imap-pop3.yaml
```

It owns no mailbox and keeps no accounts: every POP3 command is answered by talking to an IMAP
server upstream, and the credentials a client presents are the ones used to authenticate there.
Nothing is stored, so nothing can leak.

## Why it exists

Some mail clients fetch only over POP3 — Gmail's "Check mail from other accounts" is the common
one — and plenty of mail servers implement only IMAP. The two are then unreachable to each other
for a reason that has nothing to do with either being wrong: POP3 is a subset of what IMAP
already does, and no one had put a translator between them.

That is all this is. A translator, not a mail store.

## Install

```sh
go install github.com/rosaldo/imap-pop3@latest
```

Or download a binary for your platform from the
[releases](https://github.com/rosaldo/imap-pop3/releases/latest) — Linux, macOS and Windows,
amd64 and arm64, with `SHA256SUMS` to verify them.

## Usage

```sh
# with the default configuration file, ./imap-pop3.yaml
imap-pop3

# or point at one
imap-pop3 --config /etc/imap-pop3.yaml
```

The smallest configuration that starts:

```yaml
tls:
  cert: /etc/letsencrypt/live/mail.example.org/fullchain.pem
  key: /etc/letsencrypt/live/mail.example.org/privkey.pem
upstreams:
  example.org:
    host: imap.example.org:993
```

Full reference in [`docs/configuration.md`](docs/configuration.md); a commented file to copy in
[`imap-pop3.example.yaml`](imap-pop3.example.yaml).

## Setting up a client

Point the client at this server with:

| setting | value |
|---|---|
| server | the host running `imap-pop3` |
| port | `995` |
| encryption | **SSL/TLS**, not STARTTLS |
| username | the **full address**, `person@example.org` |
| password | the one for the IMAP account |

The username must carry its domain: the part after `@` is what selects the upstream. A bare
`person` cannot be routed and is refused.

## Which server serves whom

The domain of the username decides. `person@example.org` goes to whatever `example.org` is mapped
to, and a domain nobody mapped is refused — there is no fallback and no guessing.

The client never gets to name its own server. An adapter that connected wherever it was told
would be a credential oracle: anyone reaching the port could test usernames and passwords against
any host on the internet, from this machine's address and on its reputation.

## TLS is not optional

The server refuses to start without a certificate that loads. There is no plaintext mode and no
downgrade: this process carries someone's mailbox password to a remote server, so a missing or
broken certificate is a reason to stop, never a reason to serve the same thing in the clear.

It also refuses to start with an empty upstream map, or on a misspelled key in the configuration
— failures that would otherwise produce a server that looks healthy while turning every user
away.

## What it does not do

It does not go the other way. Serving IMAP from a POP3 source is a different program, and the
reason is structural rather than a matter of effort: POP3 has no folders, no flags (`\Seen`,
`\Answered`, `\Flagged`), no server-side search and no `UIDVALIDITY` — and IMAP requires all
five. None of it can be translated, because none of it exists on the POP3 side; it would have to
be invented and persisted, which means a database and a full IMAP server.

IMAP is a superset of POP3. Going down from the superset to the subset is translation; going up
is invention. Only the descent lives here.

It also serves exactly one mailbox per account, `INBOX` unless configured otherwise. POP3 has no
concept of folders, so there is nothing to select.

## Supported commands

`USER`, `PASS`, `STAT`, `LIST`, `UIDL`, `RETR`, `TOP`, `DELE`, `RSET`, `NOOP`, `CAPA`, `QUIT` —
RFC 1939 with the `UIDL` and `TOP` optional commands, and `CAPA` from RFC 2449.

`APOP` is not implemented: it would require the server to know the password, which is the one
thing this design refuses to do.

## All flags

```
--config string   path to the configuration file (default "imap-pop3.yaml")
--version         print the version and exit
```

Everything else is in the configuration file. See
[`docs/configuration.md`](docs/configuration.md).

## Releasing

```sh
./commit.sh feat "what changed"   # gate → version bump → CHANGELOG → tag
./push.sh                         # push the commits and the tag; CI builds and publishes
./push.sh --full                  # ...or build the binaries here and upload them
```

Both are shortcuts to `scripts/`. Pushing a `vX.Y.Z` tag starts the release workflow, which
cross-compiles and publishes; `--full` does the same locally, for when the workflow cannot run.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — the design and the decisions behind it.
- [`docs/configuration.md`](docs/configuration.md) — every field, and what makes the server
  refuse to start.

## Credits

The IMAP side is [go-imap](https://github.com/emersion/go-imap) (MIT), by Simon Ser — client,
server and the in-memory server the tests run against. Thank you.

The protocol itself is [RFC 1939](https://www.rfc-editor.org/rfc/rfc1939), with `CAPA` from
[RFC 2449](https://www.rfc-editor.org/rfc/rfc2449).

## License

MIT.
