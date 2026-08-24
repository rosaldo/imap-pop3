# Configuration

One YAML file, given with `--config` (default: `./imap-pop3.yaml`). A commented copy to start
from lives in [`imap-pop3.example.yaml`](../imap-pop3.example.yaml).

## The whole file

```yaml
listen: ":995"

tls:
  cert: /etc/letsencrypt/live/mail.example.org/fullchain.pem
  key: /etc/letsencrypt/live/mail.example.org/privkey.pem

timeout: 10m

upstreams:
  example.org:
    host: imap.example.org:993
    mailbox: INBOX
  other.test:
    host: mail.other.test:993
```

## Fields

| field | required | default | what it is |
|---|---|---|---|
| `listen` | no | `:995` | address to serve POP3 on |
| `tls.cert` | **yes** | — | certificate chain, PEM |
| `tls.key` | **yes** | — | private key, PEM |
| `timeout` | no | `10m` | how long a single command may take |
| `upstreams` | **yes** | — | domain → IMAP server |
| `upstreams.<domain>.host` | **yes** | — | `host:port`, normally port 993 |
| `upstreams.<domain>.mailbox` | no | `INBOX` | which mailbox to expose |

### `listen`

Any address Go's `net.Listen` accepts: `:995`, `127.0.0.1:995`, `[::1]:995`. Port 995 is where
clients expect implicit-TLS POP3.

Binding below 1024 needs privilege — a systemd unit with
`AmbientCapabilities=CAP_NET_BIND_SERVICE`, or a forward from something in front.

### `tls`

The certificate has to be valid for **the name clients connect to**, not the name of the IMAP
server behind it. Clients verify the chain; a self-signed certificate will be refused by anything
that is not configured to trust it.

Both fields are required, and the pair is loaded at boot: a path that does not exist, or a key
that does not match the certificate, stops the process.

### `timeout`

Bounds one command, in Go's duration syntax (`30s`, `10m`, `1h`). RFC 1939 asks for an autologout
timer of at least ten minutes, which is the default. It also bounds the write side, so a client
that stops reading cannot hold a connection open indefinitely.

### `upstreams`

The domain of the username selects the entry: `person@example.org` is served by whatever
`example.org` maps to. Domains must be written in lowercase; matching itself is
case-insensitive, so a client typing `person@EXAMPLE.ORG` still resolves.

A username whose domain is not in the map — or one with no `@` at all — is refused. There is no
fallback, and the client cannot name a server of its own: see
[`docs/architecture.md`](architecture.md#the-upstream-map-is-closed) for why that matters.

`mailbox` exists because POP3 has no folders: exactly one is exposed per account, and `INBOX` is
the sensible default.

## What makes the server refuse to start

All of these fail at boot, loudly, instead of producing a server that looks healthy:

| what | why it is fatal |
|---|---|
| `tls.cert` or `tls.key` missing | there is no plaintext mode; a mail password must not be downgraded because a path was wrong |
| the certificate does not load | same, and better found now than at the first connection |
| `upstreams` empty or absent | every login would be refused while the process looked fine |
| an upstream `host` without a port | `imap.example.org` is ambiguous; `imap.example.org:993` is not |
| an upstream domain with uppercase | it would never match a lowercased lookup, and the mistake is invisible |
| an unknown key in the file | `upstream:` instead of `upstreams:` would leave the map empty and look like a server bug |

That last one is why the file is parsed strictly. A typo that YAML would otherwise ignore becomes
an error naming the line.

## Running it

There is nothing to install beyond the binary and this file. A minimal systemd unit:

```ini
[Unit]
Description=imap-pop3
After=network-online.target

[Service]
ExecStart=/usr/local/bin/imap-pop3 --config /etc/imap-pop3.yaml
Restart=on-failure
DynamicUser=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
# The process reads a certificate and talks to the network. It needs nothing else.
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
```

Give the service read access to the certificate and key, and nothing more: there is no state
directory to create, because there is no state.

## Client settings

| setting | value |
|---|---|
| server | the host running `imap-pop3` |
| port | `995` |
| encryption | SSL/TLS, not STARTTLS |
| username | the full address, `person@example.org` |
| password | the one for the IMAP account |

The username must include the domain. Without it there is nothing to route on, and the login is
refused — which reads as a wrong password if you are not expecting it.
