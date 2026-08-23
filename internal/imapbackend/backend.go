// Package imapbackend serves POP3 sessions out of an IMAP server.
//
// It holds no accounts and no messages: the credentials a client presents over POP3 are the ones
// used to log in upstream, and everything a session reports is read from there.
package imapbackend

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/rosaldo/imap-pop3/internal/pop3"
)

// Upstream is one IMAP server this adapter is allowed to reach.
type Upstream struct {
	// Host is "host:port", normally port 993.
	Host string
	// Mailbox to expose. POP3 has no concept of folders, so exactly one is served; empty means
	// INBOX.
	Mailbox string
}

// Config is what the operator declares.
type Config struct {
	// Upstreams maps the domain part of a username to the server that serves it.
	//
	// The map is closed on purpose. Letting a client name its own server — say
	// "user@domain@imap.anywhere.net" — would turn this into a credential oracle: anyone who
	// reached the port could test usernames and passwords against any server on the internet,
	// from this machine's address and on its reputation.
	Upstreams map[string]Upstream

	// Logger records what the operator needs to see. It never receives credentials.
	Logger *slog.Logger
}

type dialFunc func(ctx context.Context, host string) (*imapclient.Client, error)

// Backend implements pop3.Backend.
type Backend struct {
	cfg  Config
	dial dialFunc
}

func New(cfg Config) *Backend {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Backend{cfg: cfg, dial: dialTLS}
}

func dialTLS(_ context.Context, host string) (*imapclient.Client, error) {
	// Implicit TLS. Plain IMAP is not offered even as an option: this connection carries the
	// user's password to a server that is, by definition, somewhere else.
	return imapclient.DialTLS(host, nil)
}

// Open resolves the upstream from the username's domain, authenticates there with the exact
// credentials received, and takes a snapshot of the mailbox.
func (b *Backend) Open(ctx context.Context, user, pass string) (pop3.Mailbox, error) {
	up, ok := b.resolve(user)
	if !ok {
		// The client is told only "authentication failed" (pop3 flattens every error), while the
		// operator gets the real reason — a domain nobody configured is a misconfiguration, not
		// an attack, and it would otherwise be invisible.
		b.cfg.Logger.Warn("no upstream configured for user's domain", "user", user)
		return nil, pop3.ErrAuth
	}

	c, err := b.dial(ctx, up.Host)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", up.Host, err)
	}

	if err := c.Login(user, pass).Wait(); err != nil {
		_ = c.Close()
		// Wrapped as ErrAuth so the caller does not log it: a wrong password is the client's
		// business, and logging every one of them is how a log fills up during a brute force.
		return nil, fmt.Errorf("%w: %v", pop3.ErrAuth, err)
	}

	name := up.Mailbox
	if name == "" {
		name = "INBOX"
	}
	sel, err := c.Select(name, nil).Wait()
	if err != nil {
		_ = c.Logout().Wait()
		_ = c.Close()
		return nil, fmt.Errorf("select %s: %w", name, err)
	}

	msgs, err := snapshot(c, sel.NumMessages)
	if err != nil {
		_ = c.Logout().Wait()
		_ = c.Close()
		return nil, fmt.Errorf("snapshot: %w", err)
	}

	return &Mailbox{c: c, uidValidity: sel.UIDValidity, msgs: msgs}, nil
}

// resolve picks the upstream from the domain of the address.
func (b *Backend) resolve(user string) (Upstream, bool) {
	// LastIndex, not Index: the local part of an address may itself contain a quoted "@", and
	// the domain is always what follows the final one.
	i := strings.LastIndex(user, "@")
	if i < 0 || i == len(user)-1 {
		return Upstream{}, false
	}
	up, ok := b.cfg.Upstreams[strings.ToLower(user[i+1:])]
	return up, ok
}

// message is one entry of the snapshot taken at login.
type message struct {
	uid  imap.UID
	size int64
}

// snapshot reads the message list once, at login.
//
// POP3 requires the mailbox to look frozen for the length of a session: message numbers are
// positional and must not shift, so anything that arrives mid-session has to stay invisible
// until the next one. Reading once is what makes that true.
func snapshot(c *imapclient.Client, numMessages uint32) ([]message, error) {
	if numMessages == 0 {
		return nil, nil
	}
	var set imap.SeqSet
	set.AddRange(1, numMessages)

	buf, err := c.Fetch(set, &imap.FetchOptions{UID: true, RFC822Size: true}).Collect()
	if err != nil {
		return nil, err
	}

	msgs := make([]message, 0, len(buf))
	for _, m := range buf {
		msgs = append(msgs, message{uid: m.UID, size: m.RFC822Size})
	}
	return msgs, nil
}

// Mailbox is one authenticated session against the upstream.
type Mailbox struct {
	mu          sync.Mutex
	c           *imapclient.Client
	uidValidity uint32
	msgs        []message
}

func (m *Mailbox) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.c == nil {
		return nil
	}
	c := m.c
	m.c = nil
	_ = c.Logout().Wait()
	return c.Close()
}

// uidl builds the permanent identifier POP3 reports for a message.
//
// The IMAP UID alone is NOT enough. It is unique only within one UIDVALIDITY, and when a mailbox
// is recreated the server issues a new UIDVALIDITY and recycles UIDs from 1. A client that
// stored 1,2,3 would then see 1,2,3 pointing at different messages: it either skips everything,
// believing it already has them, or downloads the mailbox again as duplicates. Pairing the two
// makes the identifier survive that.
//
// RFC 1939 §7 caps the identifier at 70 characters of printable ASCII; two 32-bit numbers and a
// dot use at most 21.
func uidl(uidValidity uint32, uid imap.UID) string {
	return fmt.Sprintf("%d.%d", uidValidity, uid)
}

// Messages returns the snapshot taken at login.
func (m *Mailbox) Messages() []pop3.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]pop3.Message, len(m.msgs))
	for i, msg := range m.msgs {
		out[i] = pop3.Message{Size: msg.size, UID: uidl(m.uidValidity, msg.uid)}
	}
	return out
}

// WriteMessage streams the whole message to w.
func (m *Mailbox) WriteMessage(ctx context.Context, index int, w io.Writer) error {
	return m.writeSection(ctx, index, w, &imap.FetchItemBodySection{Peek: true}, -1)
}

// WriteTop streams the headers plus the first n lines of the body.
//
// Two fetches rather than one with both sections: the order the server returns sections in is
// its choice, and a stream cannot be reordered after the fact. Asking for the header first and
// the text second makes the order ours.
func (m *Mailbox) WriteTop(ctx context.Context, index, n int, w io.Writer) error {
	header := &imap.FetchItemBodySection{Specifier: imap.PartSpecifierHeader, Peek: true}
	if err := m.writeSection(ctx, index, w, header, -1); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	text := &imap.FetchItemBodySection{Specifier: imap.PartSpecifierText, Peek: true}
	return m.writeSection(ctx, index, w, text, n)
}

// writeSection copies one body section of one message into w, streaming it. A maxLines above
// zero stops after that many lines, which is what TOP needs.
//
// BODY.PEEK is used throughout: plain BODY[] sets \Seen upstream, and a POP3 client fetching
// mail must not silently mark messages as read in someone's IMAP mailbox.
func (m *Mailbox) writeSection(ctx context.Context, index int, w io.Writer,
	section *imap.FetchItemBodySection, maxLines int) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.c == nil {
		return errors.New("mailbox is closed")
	}
	if index < 0 || index >= len(m.msgs) {
		return fmt.Errorf("no message at index %d", index)
	}

	cmd := m.c.Fetch(imap.UIDSetNum(m.msgs[index].uid), &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{section},
	})
	defer func() { _ = cmd.Close() }()

	for {
		msg := cmd.Next()
		if msg == nil {
			break
		}
		for {
			item := msg.Next()
			if item == nil {
				break
			}
			body, ok := item.(imapclient.FetchItemDataBodySection)
			if !ok {
				continue
			}
			if err := copySection(w, body.Literal, maxLines); err != nil {
				return err
			}
		}
	}
	return cmd.Close()
}

// copySection copies r into w, optionally stopping after maxLines lines.
func copySection(w io.Writer, r io.Reader, maxLines int) error {
	if maxLines < 0 {
		_, err := io.Copy(w, r)
		return err
	}
	// Line-bounded copy for TOP. The reader is drained either way: leaving bytes unread would
	// desynchronise the IMAP connection, which is shared by the rest of the session.
	br := bufio.NewReader(r)
	written := 0
	for {
		line, err := br.ReadBytes('\n')
		if written < maxLines && len(line) > 0 {
			if _, werr := w.Write(line); werr != nil {
				_, _ = io.Copy(io.Discard, br)
				return werr
			}
			written++
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}
