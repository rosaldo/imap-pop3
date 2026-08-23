// Package pop3 implements the server side of RFC 1939, backed by something that is not a
// mailbox of its own.
package pop3

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"
)

// ErrAuth is what a Backend returns when the credentials are refused. It is the only error the
// client is told anything about, and even then only as a flat "authentication failed": whether
// the account exists, whether the upstream is down, or how it phrased the rejection are all
// details that help someone probing and nobody else.
var ErrAuth = errors.New("authentication failed")

// Backend turns credentials into an open mailbox. The credentials arrive from the client and are
// used as they are — this server keeps no account database of its own.
type Backend interface {
	Open(ctx context.Context, user, pass string) (Mailbox, error)
}

// Mailbox is one authenticated view of an upstream mailbox, held for the length of a session.
type Mailbox interface {
	Close() error
}

// Config carries what the operator sets. The zero value is usable: the timeouts fall back to the
// defaults below.
type Config struct {
	// Timeout bounds a single client command. RFC 1939 §8 requires an autologout timer of at
	// least 10 minutes, and something has to bound a connection that opens and then says
	// nothing at all — otherwise every idle socket is a goroutine held forever.
	Timeout time.Duration

	// Logger receives operational faults. It never receives credentials: a password that reaches
	// a log file has escaped the pass-through promise this server is built on.
	Logger *slog.Logger
}

const defaultTimeout = 10 * time.Minute

// Server accepts POP3 connections on a listener it is handed. It does not create the listener
// itself, which is what lets the caller wrap it in TLS.
type Server struct {
	backend Backend
	cfg     Config

	mu       sync.Mutex
	listener net.Listener
	closing  bool
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
}

// New builds a server. Nothing is listening until Serve is called.
func New(backend Backend, cfg Config) *Server {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Server{backend: backend, cfg: cfg, conns: map[net.Conn]struct{}{}}
}

// Serve accepts connections until the listener fails or Shutdown is called. It blocks.
//
// On a failed Accept it RETURNS. The tempting alternative — logging and continuing — turns a
// closed listener into a hot loop that spins on the same error forever, burning a core and
// filling the log. Accept has no error that is worth retrying blindly.
func (s *Server) Serve(l net.Listener) error {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.listener = l
	s.mu.Unlock()

	for {
		conn, err := l.Accept()
		if err != nil {
			s.mu.Lock()
			closing := s.closing
			s.mu.Unlock()
			if closing {
				return nil
			}
			return err
		}

		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
				_ = conn.Close()
			}()
			s.serveConn(conn)
		}()
	}
}

// Shutdown stops accepting, drops the connections still open and waits for their goroutines to
// finish, or until ctx is done.
//
// Open POP3 connections are closed rather than drained. A client that has issued DELE but not
// QUIT has deleted nothing (see session.go), so cutting the connection is the safe outcome —
// waiting for an idle client to say QUIT would hold shutdown for the whole autologout timer.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closing = true
	if s.listener != nil {
		_ = s.listener.Close()
	}
	for conn := range s.conns {
		_ = conn.Close()
	}
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
