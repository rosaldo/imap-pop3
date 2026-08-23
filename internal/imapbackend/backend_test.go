package imapbackend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"

	"github.com/rosaldo/imap-pop3/internal/pop3"
)

type literal struct {
	*bytes.Reader
	size int64
}

func (l literal) Size() int64 { return l.size }

func newLiteral(s string) imap.LiteralReader {
	return literal{Reader: bytes.NewReader([]byte(s)), size: int64(len(s))}
}

// startIMAP brings up a real in-memory IMAP server holding one user with n messages, and returns
// its address.
func startIMAP(t *testing.T, users []string, pass string, n int) string {
	t.Helper()

	mem := imapmemserver.New()
	for _, user := range users {
		u := imapmemserver.NewUser(user, pass)
		if err := u.Create("INBOX", nil); err != nil && !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("create INBOX: %v", err)
		}
		for i := 0; i < n; i++ {
			msg := fmt.Sprintf("Subject: message %d\r\n\r\nbody of message %d\r\n", i+1, i+1)
			if _, err := u.Append("INBOX", newLiteral(msg), &imap.AppendOptions{}); err != nil {
				t.Fatalf("append: %v", err)
			}
		}
		mem.AddUser(u)
	}

	srv := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		},
		Caps: imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapIMAP4rev2: {}},
		// The test server speaks plain TCP, so it must be told to accept a login without TLS.
		// This is a property of the FIXTURE, never of the adapter: dialTLS is what production
		// uses, and there is no switch that turns it off.
		InsecureAuth: true,
	})

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })

	return l.Addr().String()
}

// newTestBackend wires the backend to plain TCP, since the in-memory server speaks no TLS.
// Production always dials TLS (see dialTLS); this replacement exists only to make the upstream
// reachable from a test.
func newTestBackend(cfg Config) *Backend {
	b, _ := newTestBackendCounting(cfg)
	return b
}

// newTestBackendCounting also reports how many times the upstream was dialled.
//
// The count is what separates "the domain was refused" from "the domain was accepted and the
// login failed": both surface as pop3.ErrAuth, so asserting on the error alone cannot tell a
// working guard from a broken one that happens to fail for another reason.
func newTestBackendCounting(cfg Config) (*Backend, *int) {
	dials := new(int)
	b := New(cfg)
	b.dial = func(_ context.Context, host string) (*imapclient.Client, error) {
		*dials++
		return imapclient.DialInsecure(host, nil)
	}
	return b, dials
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestRoutesByDomain is the point of multi-upstream: two domains must reach two different
// servers. The mailboxes hold different message counts, so a session that landed on the wrong
// server is visible rather than merely suspected.
func TestRoutesByDomain(t *testing.T) {
	// Same username and password on both servers, different message counts. That way a session
	// that lands on the wrong upstream still authenticates, and the mistake shows up as the
	// wrong mailbox contents — which is what the assertion below actually claims to catch. With
	// distinct credentials the test would fail on the login instead, passing for a reason that
	// has nothing to do with routing.
	// BOTH usernames exist on BOTH servers, with the same password — only the message counts
	// differ. So a session that lands on the wrong upstream still logs in, and the mistake shows
	// up as the wrong mailbox contents, which is what the assertion below claims to catch. If
	// only one server knew each username, a routing bug would fail on the login instead, and the
	// test would pass for a reason that has nothing to do with routing.
	const pass = "same-pw"
	both := []string{"shared@one.test", "shared@two.test"}
	addrOne := startIMAP(t, both, pass, 2)
	addrTwo := startIMAP(t, both, pass, 5)

	b := newTestBackend(Config{
		Logger: discardLogger(),
		Upstreams: map[string]Upstream{
			"one.test": {Host: addrOne},
			"two.test": {Host: addrTwo},
		},
	})

	for _, tc := range []struct {
		user, pass string
		want       int
	}{
		{"shared@one.test", pass, 2},
		{"shared@two.test", pass, 5},
	} {
		box, err := b.Open(context.Background(), tc.user, tc.pass)
		if err != nil {
			t.Fatalf("Open(%s): %v", tc.user, err)
		}
		mb, ok := box.(*Mailbox)
		if !ok {
			t.Fatalf("Open returned %T, want *Mailbox", box)
		}
		if got := len(mb.msgs); got != tc.want {
			t.Errorf("%s: snapshot has %d messages, want %d — the session reached the wrong upstream",
				tc.user, got, tc.want)
		}
		if mb.uidValidity == 0 {
			t.Errorf("%s: UIDVALIDITY is 0 — UIDL cannot be made stable without it", tc.user)
		}
		if err := box.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}
}

func TestCredentialsAreRefusedWhenWrong(t *testing.T) {
	addr := startIMAP(t, []string{"a@one.test"}, "right", 1)
	b := newTestBackend(Config{
		Logger:    discardLogger(),
		Upstreams: map[string]Upstream{"one.test": {Host: addr}},
	})

	_, err := b.Open(context.Background(), "a@one.test", "wrong")
	if err == nil {
		t.Fatal("Open succeeded with the wrong password")
	}
	if !errors.Is(err, pop3.ErrAuth) {
		t.Errorf("got %v, want it to wrap pop3.ErrAuth — otherwise every failed login is logged "+
			"as an operational fault, which is how a brute force fills the disk", err)
	}
}

func TestUsernameWithoutRoutableDomain(t *testing.T) {
	addr := startIMAP(t, []string{"a@one.test"}, "pw", 1)
	b, dials := newTestBackendCounting(Config{
		Logger:    discardLogger(),
		Upstreams: map[string]Upstream{"one.test": {Host: addr}},
	})

	for _, user := range []string{
		"nobody@unconfigured.test", // domain nobody declared
		"plainuser",                // no domain at all
		"trailing@",                // empty domain
	} {
		if _, err := b.Open(context.Background(), user, "pw"); !errors.Is(err, pop3.ErrAuth) {
			t.Errorf("Open(%q) returned %v, want pop3.ErrAuth", user, err)
		}
	}

	// The assertion that actually bites. An unroutable username must be turned away BEFORE any
	// connection is made: if the adapter dialled and let the upstream reject the login, the
	// error would look identical while the guard was doing nothing.
	if *dials != 0 {
		t.Errorf("the upstream was dialled %d times for unroutable usernames — they are being "+
			"turned away by the upstream's rejection, not by the domain map", *dials)
	}
}

// TestClientCannotChooseUpstream: the address is not a route. If a username could name its own
// server, this adapter would become a way to test credentials against any host on the internet.
func TestClientCannotChooseUpstream(t *testing.T) {
	addr := startIMAP(t, []string{"a@one.test"}, "pw", 1)
	b := newTestBackend(Config{
		Logger:    discardLogger(),
		Upstreams: map[string]Upstream{"one.test": {Host: addr}},
	})

	// The domain here is the address of a real, reachable server — and it must still be refused,
	// because it is not in the map.
	if _, err := b.Open(context.Background(), "a@one.test@"+addr, "pw"); !errors.Is(err, pop3.ErrAuth) {
		t.Errorf("a username naming its own host was accepted (%v)", err)
	}
}

// TestDomainMatchIsCaseInsensitive: domains are case-insensitive, and a client that capitalises
// them must not be told its password is wrong.
func TestDomainMatchIsCaseInsensitive(t *testing.T) {
	addr := startIMAP(t, []string{"a@one.test"}, "pw", 1)
	b := newTestBackend(Config{
		Logger:    discardLogger(),
		Upstreams: map[string]Upstream{"one.test": {Host: addr}},
	})

	if _, ok := b.resolve("a@ONE.TEST"); !ok {
		t.Error("a@ONE.TEST did not resolve — domain matching is case-sensitive")
	}
}

// TestNoCredentialsInLogs: the operator log carries the username, never the password.
func TestNoCredentialsInLogs(t *testing.T) {
	var buf bytes.Buffer
	b := newTestBackend(Config{
		Logger:    slog.New(slog.NewTextHandler(&buf, nil)),
		Upstreams: map[string]Upstream{},
	})

	_, _ = b.Open(context.Background(), "someone@nowhere.test", "hunter2-should-never-appear")

	if got := buf.String(); strings.Contains(got, "hunter2-should-never-appear") {
		t.Errorf("the password reached the log:\n%s", got)
	}
}

// TestUidlPairsValidityWithUID is the guard for the identifier a client stores forever.
//
// The IMAP UID alone is unique only inside one UIDVALIDITY. When a mailbox is recreated the
// server hands out a new UIDVALIDITY and starts UIDs at 1 again, so an identifier built from the
// UID alone would repeat — and the client would either skip mail it never saw or download the
// mailbox twice.
func TestUidlPairsValidityWithUID(t *testing.T) {
	// Same UID, different mailbox incarnations: the identifiers must differ.
	if a, b := uidl(1000, 1), uidl(2000, 1); a == b {
		t.Errorf("UIDVALIDITY is being ignored: %q == %q — recycled UIDs will collide", a, b)
	}
	// Same incarnation, different UIDs: also distinct.
	if a, b := uidl(1000, 1), uidl(1000, 2); a == b {
		t.Errorf("the UID is being ignored: %q == %q", a, b)
	}
	// And stable: the same inputs always give the same answer.
	if a, b := uidl(1000, 7), uidl(1000, 7); a != b {
		t.Errorf("not deterministic: %q != %q", a, b)
	}

	// RFC 1939 §7: at most 70 characters, printable ASCII (0x21..0x7E).
	got := uidl(4294967295, 4294967295)
	if len(got) > 70 {
		t.Errorf("identifier %q is %d chars, over the RFC's 70", got, len(got))
	}
	for _, r := range got {
		if r < 0x21 || r > 0x7E {
			t.Errorf("identifier %q holds a character outside 0x21..0x7E: %q", got, r)
		}
	}
}

// TestUidlIsStableAcrossSessions: two logins to the same untouched mailbox must report the same
// identifiers, or a client re-downloads everything on every poll.
func TestUidlIsStableAcrossSessions(t *testing.T) {
	addr := startIMAP(t, []string{"a@one.test"}, "pw", 3)
	b := newTestBackend(Config{
		Logger:    discardLogger(),
		Upstreams: map[string]Upstream{"one.test": {Host: addr}},
	})

	read := func() []string {
		box, err := b.Open(context.Background(), "a@one.test", "pw")
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer func() { _ = box.Close() }()
		var out []string
		for _, m := range box.Messages() {
			out = append(out, m.UID)
		}
		return out
	}

	first, second := read(), read()
	if len(first) != 3 {
		t.Fatalf("got %d messages, want 3", len(first))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Errorf("message %d changed identity between sessions: %q then %q",
				i+1, first[i], second[i])
		}
	}
}
