# imap-pop3

Serve an IMAP mailbox over POP3.

Some mail clients can only fetch from a POP3 server. Some mail servers only speak IMAP. This is
the adapter between the two: a POP3 server that owns no mailbox of its own and answers every
command by talking to an IMAP server upstream.

## What it is

- A protocol adapter. **No storage, no database, no user accounts.**
- Credentials are **passed through**: the `USER`/`PASS` received over POP3 are the ones used to
  log in to the IMAP server. Nothing is stored, so nothing can leak.
- One POP3 connection opens one IMAP session, and it lives until `QUIT`.
- Multiple upstreams: which IMAP server to use is resolved from the **domain** of the username.

## What it is not

**It does not go the other way.** Serving IMAP from a POP3 source is a different program, and the
reason is structural rather than a matter of effort: POP3 has no folders, no flags (`\Seen`,
`\Answered`, `\Flagged`), no server-side search and no `UIDVALIDITY` — and IMAP requires all five.
None of it can be translated, because none of it exists on the POP3 side; it would have to be
invented and persisted, which means a database and a full IMAP server. That is what `fetchmail`
paired with `dovecot` already does.

IMAP is a superset of POP3. Going down from the superset to the subset is translation; going up
is invention. Only the descent lives here.

## Configuration

Which upstream serves a user is decided by the domain of the address they log in with:

```yaml
upstreams:
  example.org: { host: "imap.example.org:993", mailbox: "INBOX" }
  other.test:  { host: "mail.other.test:993",  mailbox: "INBOX" }
```

A username whose domain is not in the map — or a username with no `@` at all — is rejected. There
is no implicit fallback, and **the client never gets to name the server**: an adapter that
connected wherever the client asked would be a credential oracle against third parties, testing
usernames and passwords anywhere in the world from this machine's address.

TLS is not affected by having several upstreams: clients connect to one hostname, this server's,
so one certificate covers them all.

## Status

Early. See `CHANGELOG.md`.

## License

MIT
