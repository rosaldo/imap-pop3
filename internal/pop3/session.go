package pop3

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

func nowAdd(d time.Duration) time.Time { return time.Now().Add(d) }

func (s *session) log(format string, a ...any) {
	s.srv.cfg.Logger.Warn(fmt.Sprintf(format, a...))
}

// state is where a session sits in the RFC 1939 flow. TRANSACTION is only reached by a
// successful PASS, and every mailbox command is refused before that.
type state int

const (
	authorization state = iota
	transaction
)

// maxLineLen caps a command line. RFC 1939 §3 puts commands at 255 octets at most; the extra
// room is slack for long usernames. The cap is what stops a client from making the server hold
// an unbounded line in memory by never sending a newline.
const maxLineLen = 1024

func (s *Server) serveConn(conn net.Conn) {
	sess := &session{srv: s, conn: conn, r: bufio.NewReaderSize(conn, maxLineLen)}
	sess.run()
}

type session struct {
	srv   *Server
	conn  net.Conn
	r     *bufio.Reader
	state state

	user string  // set by USER, only meaningful until PASS decides
	box  Mailbox // non-nil exactly in TRANSACTION
}

func (s *session) run() {
	defer func() {
		if s.box != nil {
			_ = s.box.Close()
		}
	}()

	s.reply("+OK POP3 server ready")

	for {
		line, err := s.readLine()
		if err != nil {
			return // client hung up, timed out, or sent an oversized line
		}

		cmd, args, rest := parse(line)
		if cmd == "QUIT" {
			s.quit()
			return
		}
		if !s.dispatch(cmd, args, rest) {
			return
		}
	}
}

// dispatch runs one command. It reports whether the session continues.
func (s *session) dispatch(cmd string, args []string, rest string) bool {
	switch cmd {
	case "CAPA":
		// RFC 2449. Advertised now because a client checks capabilities before it trusts a
		// command exists; TOP and UIDL land in later stories and join this list there.
		s.reply("+OK Capability list follows")
		s.reply("USER")
		s.reply(".")
	case "USER":
		if s.state != authorization {
			s.reply("-ERR already authenticated")
			break
		}
		if len(args) != 1 {
			s.reply("-ERR USER requires exactly one argument")
			break
		}
		s.user = args[0]
		s.reply("+OK")
	case "PASS":
		s.pass(rest)
	case "NOOP":
		// TRANSACTION-only per RFC 1939 §5: before authentication it must not become a way to
		// hold a connection open for free.
		if s.state != transaction {
			s.reply("-ERR command valid only after authentication")
			break
		}
		s.reply("+OK")
	default:
		s.reply("-ERR unknown command")
	}
	return true
}

func (s *session) pass(rest string) {
	if s.state != authorization {
		s.reply("-ERR already authenticated")
		return
	}
	if s.user == "" {
		s.reply("-ERR USER required first")
		return
	}
	// The password is the rest of the line VERBATIM. RFC 1939 §7 allows spaces inside it, and
	// rebuilding it from whitespace-split fields would corrupt any password containing two
	// consecutive spaces — a silent wrong-password that looks like a server bug.
	if rest == "" {
		s.reply("-ERR PASS requires an argument")
		return
	}
	pass := rest

	ctx, cancel := context.WithTimeout(context.Background(), s.srv.cfg.Timeout)
	defer cancel()

	box, err := s.srv.backend.Open(ctx, s.user, pass)
	if err != nil {
		// Every failure looks the same to the client, whether the credentials were wrong or the
		// upstream was unreachable. Telling them apart is a gift to whoever is probing, and the
		// distinction is useless to a legitimate client.
		if !errors.Is(err, ErrAuth) {
			s.log("upstream open failed for %q: %v", s.user, err)
		}
		// Per RFC 1939 the session stays in AUTHORIZATION, so the user must be given again —
		// otherwise a stale USER pairs with a fresh PASS.
		s.user = ""
		s.reply("-ERR authentication failed")
		return
	}

	s.box = box
	s.state = transaction
	s.reply("+OK mailbox ready")
}

func (s *session) quit() {
	// In AUTHORIZATION there is nothing to commit. In TRANSACTION the UPDATE state belongs to
	// the story that introduces DELE; until then QUIT only closes.
	s.reply("+OK bye")
}

// readLine reads one CRLF-terminated command, bounded by both the deadline and maxLineLen.
func (s *session) readLine() (string, error) {
	if err := s.conn.SetReadDeadline(nowAdd(s.srv.cfg.Timeout)); err != nil {
		return "", err
	}
	line, err := s.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > maxLineLen {
		return "", io.ErrShortBuffer
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (s *session) reply(format string, a ...any) {
	// A write deadline as well: a client that stops reading must not pin the goroutine, which is
	// the mirror image of the read timeout.
	_ = s.conn.SetWriteDeadline(nowAdd(s.srv.cfg.Timeout))
	_, _ = fmt.Fprintf(s.conn, format+"\r\n", a...)
}

// parse splits a command line three ways: the verb, the whitespace-split arguments, and the
// remainder of the line untouched.
//
// The verb is upper-cased because RFC 1939 §3 makes commands case-insensitive. The untouched
// remainder exists for PASS: a password may contain runs of spaces, and Fields collapses them,
// so anything rebuilt from the split fields is not what the user typed.
func parse(line string) (verb string, args []string, rest string) {
	trimmed := strings.TrimLeft(line, " \t")
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return "", nil, ""
	}
	// Exactly one separator is consumed, not a run of them: RFC 1939 §3 separates the verb from
	// its argument with a single space, so a password that legitimately begins with a space
	// survives. Trimming greedily here would eat it and fail the login for no visible reason.
	if i := strings.IndexAny(trimmed, " \t"); i >= 0 {
		rest = trimmed[i+1:]
	}
	return strings.ToUpper(fields[0]), fields[1:], rest
}
