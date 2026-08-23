package pop3

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeBackend accepts one credential pair and records what it was handed, so a test can assert
// on what actually crossed the boundary rather than on what the session meant to send.
type fakeBackend struct {
	wantUser, wantPass string
	err                error

	gotUser, gotPass string
	opened, closed   int
}

type fakeMailbox struct{ b *fakeBackend }

func (m *fakeMailbox) Close() error { m.b.closed++; return nil }

func (b *fakeBackend) Open(_ context.Context, user, pass string) (Mailbox, error) {
	b.gotUser, b.gotPass = user, pass
	if b.err != nil {
		return nil, b.err
	}
	if user != b.wantUser || pass != b.wantPass {
		return nil, ErrAuth
	}
	b.opened++
	return &fakeMailbox{b: b}, nil
}

// start brings up a server on a random port and returns a dial helper plus a stopper.
func start(t *testing.T, b Backend) (dial func(*testing.T) *conn, stop func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := New(b, Config{Timeout: 3 * time.Second})
	done := make(chan error, 1)
	go func() { done <- srv.Serve(l) }()

	dial = func(t *testing.T) *conn {
		t.Helper()
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return &conn{t: t, c: c, r: bufio.NewReader(c)}
	}
	stop = func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
		if err := <-done; err != nil {
			t.Errorf("Serve returned %v, want nil after Shutdown", err)
		}
	}
	return dial, stop
}

type conn struct {
	t *testing.T
	c net.Conn
	r *bufio.Reader
}

func (c *conn) send(format string, a ...any) {
	c.t.Helper()
	if _, err := fmt.Fprintf(c.c, format+"\r\n", a...); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

func (c *conn) line() string {
	c.t.Helper()
	_ = c.c.SetReadDeadline(time.Now().Add(3 * time.Second))
	s, err := c.r.ReadString('\n')
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	return strings.TrimRight(s, "\r\n")
}

func (c *conn) expectOK(what string) {
	c.t.Helper()
	if got := c.line(); !strings.HasPrefix(got, "+OK") {
		c.t.Fatalf("%s: got %q, want +OK", what, got)
	}
}

func (c *conn) expectErr(what string) {
	c.t.Helper()
	if got := c.line(); !strings.HasPrefix(got, "-ERR") {
		c.t.Fatalf("%s: got %q, want -ERR", what, got)
	}
}

func TestAuthorizationSuccess(t *testing.T) {
	b := &fakeBackend{wantUser: "someone@example.org", wantPass: "secret"}
	dial, stop := start(t, b)
	defer stop()

	c := dial(t)
	c.expectOK("greeting")
	c.send("USER someone@example.org")
	c.expectOK("USER")
	c.send("PASS secret")
	c.expectOK("PASS")

	// NOOP is TRANSACTION-only, so it doubles as proof the state actually moved.
	c.send("NOOP")
	c.expectOK("NOOP after auth")

	c.send("QUIT")
	c.expectOK("QUIT")

	if b.opened != 1 {
		t.Errorf("backend opened %d times, want 1", b.opened)
	}
}

func TestAuthorizationWrongPassword(t *testing.T) {
	b := &fakeBackend{wantUser: "someone@example.org", wantPass: "secret"}
	dial, stop := start(t, b)
	defer stop()

	c := dial(t)
	c.expectOK("greeting")
	c.send("USER someone@example.org")
	c.expectOK("USER")
	c.send("PASS wrong")
	c.expectErr("PASS with wrong password")

	// The session stays in AUTHORIZATION, and USER has been forgotten: a bare PASS must not
	// pair with the username from the failed attempt.
	c.send("PASS secret")
	c.expectErr("PASS without a fresh USER")

	c.send("NOOP")
	c.expectErr("NOOP before auth")

	if b.opened != 0 {
		t.Errorf("backend opened %d times, want 0", b.opened)
	}
}

// TestPasswordCrossesVerbatim guards the one place where a plausible implementation silently
// corrupts input: rebuilding the password from whitespace-split fields. A password with a run of
// spaces, or a leading space, comes out different — and the user sees only "wrong password".
func TestPasswordCrossesVerbatim(t *testing.T) {
	for _, pass := range []string{"two  spaces", " leading", "trailing ", "a b c", "sim'ples"} {
		t.Run(pass, func(t *testing.T) {
			b := &fakeBackend{wantUser: "u@example.org", wantPass: pass}
			dial, stop := start(t, b)
			defer stop()

			c := dial(t)
			c.expectOK("greeting")
			c.send("USER u@example.org")
			c.expectOK("USER")
			c.send("PASS %s", pass)
			c.expectOK("PASS")

			if b.gotPass != pass {
				t.Errorf("backend got password %q, want %q", b.gotPass, pass)
			}
		})
	}
}

func TestMailboxClosedWhenSessionEnds(t *testing.T) {
	b := &fakeBackend{wantUser: "u@example.org", wantPass: "p"}
	dial, stop := start(t, b)
	defer stop()

	c := dial(t)
	c.expectOK("greeting")
	c.send("USER u@example.org")
	c.expectOK("USER")
	c.send("PASS p")
	c.expectOK("PASS")
	c.send("QUIT")
	c.expectOK("QUIT")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && b.closed == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if b.closed != 1 {
		t.Errorf("mailbox closed %d times, want 1 — an upstream session was left open", b.closed)
	}
}

// TestPasswordNeverLogged: the pass-through promise is that nothing is stored. A password in a
// log file breaks it just as thoroughly as a database would.
func TestPasswordNeverLogged(t *testing.T) {
	var buf bytes.Buffer
	b := &fakeBackend{wantUser: "u@example.org", wantPass: "x", err: fmt.Errorf("upstream on fire")}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := New(b, Config{
		Timeout: 3 * time.Second,
		Logger:  slog.New(slog.NewTextHandler(&buf, nil)),
	})
	go func() { _ = srv.Serve(l) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	raw, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = raw.Close() }()
	c := &conn{t: t, c: raw, r: bufio.NewReader(raw)}
	c.expectOK("greeting")
	c.send("USER u@example.org")
	c.expectOK("USER")
	c.send("PASS hunter2-should-never-appear")
	c.expectErr("PASS with failing upstream")

	if got := buf.String(); strings.Contains(got, "hunter2-should-never-appear") {
		t.Errorf("the password reached the log:\n%s", got)
	}
}

// TestServeReturnsWhenListenerCloses is the canary for the busy loop. If Accept's error path
// were `continue` instead of a return, a closed listener would spin forever on the same error;
// here that shows up as Serve never returning, and the test failing on the timeout.
func TestServeReturnsWhenListenerCloses(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := New(&fakeBackend{}, Config{Timeout: time.Second})
	done := make(chan error, 1)
	go func() { done <- srv.Serve(l) }()

	time.Sleep(50 * time.Millisecond) // let Serve reach Accept
	_ = l.Close()                     // closed from underneath, without Shutdown

	select {
	case <-done:
		// Returned, which is the point. The error itself is the listener's, not interesting.
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after the listener closed — the Accept loop is spinning")
	}
}

// TestShutdownWaitsForConnections: Shutdown must not return while a session goroutine is still
// running, and must not leave one behind either.
func TestShutdownWaitsForConnections(t *testing.T) {
	before := runtime.NumGoroutine()

	b := &fakeBackend{wantUser: "u@example.org", wantPass: "p"}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := New(b, Config{Timeout: 30 * time.Second}) // long, so only Shutdown can end the session
	go func() { _ = srv.Serve(l) }()

	// An idle authenticated session: the goroutine is parked in a read that will not complete.
	raw, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = raw.Close() }()
	c := &conn{t: t, c: raw, r: bufio.NewReader(raw)}
	c.expectOK("greeting")
	c.send("USER u@example.org")
	c.expectOK("USER")
	c.send("PASS p")
	c.expectOK("PASS")

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown did not finish: %v — an idle session held it", err)
	}

	// Goroutine count settles asynchronously; poll rather than assert on the instant.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before+2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("goroutines went from %d to %d — Shutdown leaked session goroutines",
		before, runtime.NumGoroutine())
}
