# Architecture

One process, no storage. A POP3 server that owns no mailbox and answers each command by talking
to an IMAP server on the other side.

```
client  ──TLS──▶  imap-pop3  ──IMAP──▶  upstream
        :995      (adapter)     :993
```

Everything that exists at runtime belongs to a connection and dies with it. There is no database,
no spool, no cache and no account file.

## Translating down, never up

IMAP is a superset of POP3. Every question POP3 asks has an answer in IMAP:

| POP3 | IMAP |
|---|---|
| `STAT` | `STATUS (MESSAGES)` plus the sum of `RFC822.SIZE` |
| `LIST` | `FETCH RFC822.SIZE` |
| `UIDL` | `UIDVALIDITY` paired with `UID` |
| `RETR` | `FETCH BODY.PEEK[]` |
| `TOP n x` | `FETCH BODY.PEEK[HEADER]`, then x lines of `BODY.PEEK[TEXT]` |
| `DELE` | a mark held in the session — nothing upstream |
| `QUIT` | `STORE +FLAGS (\Deleted)` then `EXPUNGE` |

The other direction has no such table. POP3 has no folders, no flags, no server-side search and
no `UIDVALIDITY`, and IMAP requires all of them — they would have to be invented and persisted,
which is a mail store with a collector in front, not an adapter. That is why this program only
goes one way.

## Decisions worth explaining

### Credentials are passed through, never stored

The `USER` and `PASS` received over POP3 are used verbatim to log in upstream. If the IMAP server
accepts them the POP3 session is authenticated; if not, it is refused.

This is a security decision before it is a simplicity one. There is no account database to keep
in sync, no password file to protect, and no hash to leak — the authority over who gets in stays
with the mail server, where it already was. The password is not written to logs either; a test
asserts on that, because a credential in a log file breaks the promise as thoroughly as a
database would.

### The upstream map is closed

Which IMAP server serves a login is decided by the domain of the username, against a map the
operator writes.

The tempting alternative is to let the client name the server — `user@domain@imap.anywhere.net`
— which would need no configuration at all. It would also turn this into a credential oracle:
anyone who reached the port could test usernames and passwords against any host on the internet,
using this machine's address and its reputation. DNS discovery (`_imaps._tcp`, RFC 6186) has the
same defect with a network round-trip added to every login.

### The mailbox is a snapshot, taken at login

Message numbers in POP3 are positional and must not shift during a session. The message list is
therefore read once, when the session opens, and everything after that is answered from it. Mail
that arrives mid-session stays invisible until the next one.

That is not a limitation of this implementation — it is the model POP3 defines.

### `UIDL` pairs `UIDVALIDITY` with the UID

The identifier a client stores to know what it has already downloaded must mean the same thing
forever. The IMAP UID alone does not: it is unique only within one `UIDVALIDITY`, and a mailbox
that is recreated gets a new `UIDVALIDITY` with UIDs recycled from 1. A client holding `1,2,3`
would then see `1,2,3` pointing at different messages — skipping mail it never saw, or
downloading the mailbox again as duplicates.

`<UIDVALIDITY>.<UID>` survives that, and fits the 70 printable-ASCII characters RFC 1939 allows
with room to spare.

### `DELE` marks; only `QUIT` deletes

In POP3, `DELE` is a promise: the removal happens in the UPDATE state, when the client says
`QUIT`, and `RSET` withdraws it.

Expunging as each `DELE` arrives would be simpler and is wrong. A session that drops halfway
would destroy messages the client never confirmed, and with "remove from server after download"
enabled — the common setting — that is lost mail, silently, on both sides. A connection that dies
without `QUIT` leaves the mailbox exactly as it was.

When the upstream refuses the removal, `QUIT` answers `-ERR`, so the client does not record the
messages as gone.

### `UIDEXPUNGE` where the server has it

A bare `EXPUNGE` removes everything flagged `\Deleted` in the mailbox — including messages
flagged from another client, by someone else, which this session was never asked to touch. Where
the server advertises `UIDPLUS`, the expunge is scoped to the UIDs this session marked.

### `BODY.PEEK`, always

Plain `BODY[]` sets `\Seen` upstream. The same mailbox is usually read in a normal IMAP client,
and a POP3 poll quietly marking everything as read is a change nobody asked for and one that
cannot be undone, because nothing recorded what was unread.

### Bodies are streamed

Message bodies are copied from the IMAP literal straight to the wire. Buffering a message in full
to hand it over would make the server's memory a function of what somebody happened to be sent.

The dot-encoding on the way out is `net/textproto`'s, from the standard library: a body line
beginning with `.` goes out doubled, or the client reads it as the end of the message and the
rest is lost while both sides believe the transfer succeeded.

### TLS is implicit, and mandatory

The listener is TLS from the first byte, on 995. Not STARTTLS, which opens in the clear and adds
a command whose absence a client may not notice.

The server refuses to start without a certificate that loads. There is no flag to turn this off:
a process that carries mailbox passwords has no honest reason to offer a plaintext mode.

## Dependencies

Two direct, both MIT: [go-imap](https://github.com/emersion/go-imap) for the IMAP client, and
`gopkg.in/yaml.v3` for the configuration file. `go-message` and `go-sasl` come along with the
first.

Writing the IMAP client here instead was considered and rejected. What we use is seven commands
— `LOGIN`, `SELECT`, `FETCH`, `STORE`, `EXPUNGE`, `LOGOUT`, `CAPABILITY` — but the cost is not in
the commands: it is the response parser, with untagged responses arriving out of order, literals
that change how the stream is read, and server continuations. Lifting out "just the Fetch" drags
the parser along with it, so the real choice is between using the library and writing roughly a
thousand lines of protocol code. The library is ten years old, actively maintained, and pinned.

The version is pinned on purpose. `go get -u` on this dependency is a deliberate act: v2 has
been in beta since 2024, and its API can move between betas.

## What ends up in the log

One line when a session authenticates, one when it ends:

```
INFO session opened user=person@example.org messages=12
INFO session closed user=person@example.org retrieved=3 deleted=1 duration=412ms
```

A server that says nothing when it works cannot be told apart from a server nobody reached — and
that distinction is the first question asked when a client "does not work". Failures are logged
too, at warn level.

What never appears is the password. There is a test asserting on that, for the failure path and
for the success path: a credential in a log file breaks the pass-through promise as thoroughly as
a database would.

## Shape of the code

| package | what it holds |
|---|---|
| `main` | flags, configuration, TLS listener, signals |
| `internal/config` | the file, its defaults and the validation that refuses to start |
| `internal/pop3` | the protocol: connection handling, session state, commands |
| `internal/imapbackend` | the translation, and everything that talks to IMAP |

`internal/pop3` knows nothing about IMAP. It is written against two small interfaces — `Backend`,
which turns credentials into a mailbox, and `Mailbox`, which answers questions about one — so the
protocol can be tested without a mail server anywhere in sight, and the translation can be tested
against a real one.

## Testing

The unit tests cover each piece; an end-to-end test drives a full POP3 session over TLS against a
real in-memory IMAP server and then checks the effect on that server, because a translation that
agrees with itself can still be wrong.

Every behaviour worth having is paired with a check that it is really being enforced: the tests
are run again with the logic deliberately broken, and one that still passes is a test that was
not testing anything.
