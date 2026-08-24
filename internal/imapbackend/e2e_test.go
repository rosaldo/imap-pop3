// End-to-end: the whole adapter driven the way a real client would, a POP3 session over TLS
// answered from a real IMAP server, with the effect checked on that server afterwards.
//
// The unit tests each prove one piece; this proves the pieces are wired to each other — the
// class of defect where every part is correct and the assembly is not.
//
// It lives in this package rather than one of its own for a single reason: the fixture IMAP
// server speaks plain TCP, and swapping the dialler for an insecure one is only possible from
// inside. The alternative was a TLS knob on Config that production would never set, which is
// configuration invented to satisfy a test.
package imapbackend

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"

	"github.com/rosaldo/imap-pop3/internal/pop3"
)

// startIMAPWith brings up an in-memory IMAP server holding the given message bodies.
func startIMAPWith(t *testing.T, user, pass string, msgs []string) string {
	t.Helper()

	mem := imapmemserver.New()
	u := imapmemserver.NewUser(user, pass)
	if err := u.Create("INBOX", nil); err != nil && !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("create INBOX: %v", err)
	}
	for _, m := range msgs {
		if _, err := u.Append("INBOX", newLiteral(m), &imap.AppendOptions{}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	mem.AddUser(u)

	srv := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		},
		Caps:         imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapIMAP4rev2: {}},
		InsecureAuth: true, // the fixture speaks plain TCP; the adapter's own TLS is the point here
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().String()
}

// selfSigned returns a certificate for localhost plus a pool that trusts it, so the client
// verifies the chain for real instead of skipping verification.
func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// startPOP3 serves the adapter over TLS, exactly as main.go does.
func startPOP3(t *testing.T, upstreams map[string]Upstream) (addr string, pool *x509.CertPool) {
	t.Helper()
	cert, pool := selfSigned(t)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := newTestBackend(Config{Upstreams: upstreams, Logger: logger})
	srv := pop3.New(backend, pop3.Config{Timeout: 10 * time.Second, Logger: logger})

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return ln.Addr().String(), pool
}

type client struct {
	t *testing.T
	c net.Conn
	r *bufio.Reader
}

func (c *client) send(format string, a ...any) {
	c.t.Helper()
	if _, err := fmt.Fprintf(c.c, format+"\r\n", a...); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

func (c *client) line() string {
	c.t.Helper()
	_ = c.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	s, err := c.r.ReadString('\n')
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	return strings.TrimRight(s, "\r\n")
}

func (c *client) ok(what string) string {
	c.t.Helper()
	got := c.line()
	if !strings.HasPrefix(got, "+OK") {
		c.t.Fatalf("%s: got %q, want +OK", what, got)
	}
	return got
}

func (c *client) multiline() []string {
	c.t.Helper()
	var out []string
	for {
		l := c.line()
		if l == "." {
			return out
		}
		out = append(out, l)
	}
}

func (c *client) body() string {
	c.t.Helper()
	_ = c.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	out, err := io.ReadAll(textproto.NewReader(c.r).DotReader())
	if err != nil {
		c.t.Fatalf("body: %v", err)
	}
	return string(out)
}

// remaining asks the IMAP server directly what is left, which is the only answer that counts:
// the adapter's own view could agree with itself and still be wrong.
func remaining(t *testing.T, addr, user, pass string) []string {
	t.Helper()
	c, err := imapclient.DialInsecure(addr, nil)
	if err != nil {
		t.Fatalf("dial imap: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Login(user, pass).Wait(); err != nil {
		t.Fatalf("imap login: %v", err)
	}
	sel, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if sel.NumMessages == 0 {
		return nil
	}
	var set imap.SeqSet
	set.AddRange(1, sel.NumMessages)
	section := &imap.FetchItemBodySection{Peek: true}
	msgs, err := c.Fetch(set, &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{section}}).Collect()
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	var out []string
	for _, m := range msgs {
		for _, bs := range m.BodySection {
			out = append(out, string(bs.Bytes))
		}
	}
	return out
}

// TestFullSessionOverTLS walks one complete POP3 session and then checks the IMAP server.
func TestFullSessionOverTLS(t *testing.T) {
	const user, pass = "person@example.org", "s3cret"
	msgs := []string{
		"Subject: first\r\n\r\nbody of the first\r\n",
		"Subject: second\r\n\r\n.a line starting with a dot\r\nand more\r\n",
		"Subject: third\r\n\r\nbody of the third\r\n",
	}
	imapAddr := startIMAPWith(t, user, pass, msgs)
	popAddr, pool := startPOP3(t, map[string]Upstream{
		"example.org": {Host: imapAddr},
	})

	// The client verifies the certificate chain — no InsecureSkipVerify.
	raw, err := tls.Dial("tcp", popAddr, &tls.Config{RootCAs: pool, ServerName: "localhost"})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer func() { _ = raw.Close() }()
	c := &client{t: t, c: raw, r: bufio.NewReader(raw)}

	c.ok("greeting")
	c.send("USER %s", user)
	c.ok("USER")
	c.send("PASS %s", pass)
	c.ok("PASS")

	c.send("STAT")
	if got, want := c.ok("STAT"), fmt.Sprintf("+OK 3 %d", len(msgs[0])+len(msgs[1])+len(msgs[2])); got != want {
		t.Errorf("STAT: got %q, want %q", got, want)
	}

	c.send("LIST")
	c.ok("LIST")
	if lines := c.multiline(); len(lines) != 3 {
		t.Errorf("LIST returned %d lines, want 3: %v", len(lines), lines)
	}

	c.send("UIDL")
	c.ok("UIDL")
	uidls := c.multiline()
	if len(uidls) != 3 {
		t.Fatalf("UIDL returned %d lines, want 3: %v", len(uidls), uidls)
	}
	for _, l := range uidls {
		if !strings.Contains(l, ".") {
			t.Errorf("UIDL %q does not pair UIDVALIDITY with the UID", l)
		}
	}

	// The message with a leading dot is the one worth fetching: it is where an unstuffed body
	// truncates the transfer.
	c.send("RETR 2")
	c.ok("RETR")
	if got, want := c.body(), strings.ReplaceAll(msgs[1], "\r\n", "\n"); got != want {
		t.Errorf("RETR 2:\n got %q\nwant %q", got, want)
	}

	c.send("TOP 1 0")
	c.ok("TOP")
	if got := c.body(); !strings.Contains(got, "Subject: first") || strings.Contains(got, "body of the first") {
		t.Errorf("TOP 1 0 returned %q, want headers only", got)
	}

	c.send("DELE 2")
	c.ok("DELE")

	// Still three on the server: DELE has only marked it.
	if got := remaining(t, imapAddr, user, pass); len(got) != 3 {
		t.Errorf("IMAP holds %d messages before QUIT, want 3 — DELE deleted early", len(got))
	}

	c.send("QUIT")
	c.ok("QUIT")

	// And now two, with the right one gone.
	left := remaining(t, imapAddr, user, pass)
	if len(left) != 2 {
		t.Fatalf("IMAP holds %d messages after QUIT, want 2", len(left))
	}
	for _, m := range left {
		if strings.Contains(m, "Subject: second") {
			t.Error("the deleted message is still there — QUIT did not expunge it")
		}
	}
	if !strings.Contains(strings.Join(left, ""), "Subject: first") ||
		!strings.Contains(strings.Join(left, ""), "Subject: third") {
		t.Errorf("QUIT removed the wrong messages: %v", left)
	}
}

// TestSessionDroppedAfterDeleKeepsMail: the same walk, cut short. Nothing may be removed.
func TestSessionDroppedAfterDeleKeepsMail(t *testing.T) {
	const user, pass = "person@example.org", "s3cret"
	imapAddr := startIMAPWith(t, user, pass, []string{"Subject: one\r\n\r\nkeep me\r\n"})
	popAddr, pool := startPOP3(t, map[string]Upstream{"example.org": {Host: imapAddr}})

	raw, err := tls.Dial("tcp", popAddr, &tls.Config{RootCAs: pool, ServerName: "localhost"})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	c := &client{t: t, c: raw, r: bufio.NewReader(raw)}
	c.ok("greeting")
	c.send("USER %s", user)
	c.ok("USER")
	c.send("PASS %s", pass)
	c.ok("PASS")
	c.send("DELE 1")
	c.ok("DELE")

	_ = raw.Close() // no QUIT
	time.Sleep(200 * time.Millisecond)

	if got := remaining(t, imapAddr, user, pass); len(got) != 1 {
		t.Errorf("IMAP holds %d messages, want 1 — a dropped session destroyed mail", len(got))
	}
}

// TestUnknownDomainIsRefusedOverTLS: the routing guard, reached through the real server.
func TestUnknownDomainIsRefusedOverTLS(t *testing.T) {
	imapAddr := startIMAPWith(t, "person@example.org", "s3cret", []string{"Subject: x\r\n\r\ny\r\n"})
	popAddr, pool := startPOP3(t, map[string]Upstream{"example.org": {Host: imapAddr}})

	raw, err := tls.Dial("tcp", popAddr, &tls.Config{RootCAs: pool, ServerName: "localhost"})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer func() { _ = raw.Close() }()
	c := &client{t: t, c: raw, r: bufio.NewReader(raw)}

	c.ok("greeting")
	c.send("USER person@nobody.test")
	c.ok("USER")
	c.send("PASS s3cret")
	if got := c.line(); !strings.HasPrefix(got, "-ERR") {
		t.Errorf("PASS for an unconfigured domain: got %q, want -ERR", got)
	}
}

// flagsOf asks the IMAP server which flags each message carries.
func flagsOf(t *testing.T, addr, user, pass string) [][]imap.Flag {
	t.Helper()
	c, err := imapclient.DialInsecure(addr, nil)
	if err != nil {
		t.Fatalf("dial imap: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Login(user, pass).Wait(); err != nil {
		t.Fatalf("imap login: %v", err)
	}
	sel, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if sel.NumMessages == 0 {
		return nil
	}
	var set imap.SeqSet
	set.AddRange(1, sel.NumMessages)
	msgs, err := c.Fetch(set, &imap.FetchOptions{Flags: true}).Collect()
	if err != nil {
		t.Fatalf("fetch flags: %v", err)
	}
	out := make([][]imap.Flag, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, m.Flags)
	}
	return out
}

// TestFetchingDoesNotMarkSeen: RETR and TOP must use BODY.PEEK.
//
// A plain BODY[] sets \Seen upstream. The subscriber reads that same mailbox in a normal IMAP
// client, and a POP3 poll silently marking everything read is a change to their mailbox that
// nobody asked for — and one that cannot be undone, because nothing recorded what was unread.
func TestFetchingDoesNotMarkSeen(t *testing.T) {
	const user, pass = "person@example.org", "s3cret"
	imapAddr := startIMAPWith(t, user, pass, []string{
		"Subject: one\r\n\r\nbody one\r\n",
		"Subject: two\r\n\r\nbody two\r\n",
	})
	popAddr, pool := startPOP3(t, map[string]Upstream{"example.org": {Host: imapAddr}})

	for _, f := range flagsOf(t, imapAddr, user, pass) {
		for _, flag := range f {
			if flag == imap.FlagSeen {
				t.Fatal("the fixture already had \\Seen set — the test cannot prove anything")
			}
		}
	}

	raw, err := tls.Dial("tcp", popAddr, &tls.Config{RootCAs: pool, ServerName: "localhost"})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer func() { _ = raw.Close() }()
	c := &client{t: t, c: raw, r: bufio.NewReader(raw)}

	c.ok("greeting")
	c.send("USER %s", user)
	c.ok("USER")
	c.send("PASS %s", pass)
	c.ok("PASS")
	c.send("RETR 1")
	c.ok("RETR")
	_ = c.body()
	c.send("TOP 2 1")
	c.ok("TOP")
	_ = c.body()
	c.send("QUIT")
	c.ok("QUIT")

	for i, f := range flagsOf(t, imapAddr, user, pass) {
		for _, flag := range f {
			if flag == imap.FlagSeen {
				t.Errorf("message %d was marked \\Seen by a POP3 fetch — BODY.PEEK is not being used", i+1)
			}
		}
	}
}
