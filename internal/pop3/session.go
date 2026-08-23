package pop3

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"net/textproto"
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
		s.reply("TOP")
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
	case "STAT":
		s.stat()
	case "LIST":
		s.list(args)
	case "RETR":
		s.retr(args)
	case "TOP":
		s.top(args)
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

// requireTransaction refuses a mailbox command before authentication.
func (s *session) requireTransaction() bool {
	if s.state != transaction {
		s.reply("-ERR command valid only after authentication")
		return false
	}
	return true
}

// index parses a message number and validates it against the snapshot. POP3 numbers messages
// from 1; the slice is 0-based.
func (s *session) index(arg string) (int, bool) {
	n, err := strconv.Atoi(arg)
	if err != nil || n < 1 || n > len(s.box.Messages()) {
		s.reply("-ERR no such message")
		return 0, false
	}
	return n - 1, true
}

func (s *session) stat() {
	if !s.requireTransaction() {
		return
	}
	msgs := s.box.Messages()
	var total int64
	for _, m := range msgs {
		total += m.Size
	}
	s.reply("+OK %d %d", len(msgs), total)
}

func (s *session) list(args []string) {
	if !s.requireTransaction() {
		return
	}
	msgs := s.box.Messages()

	if len(args) == 1 {
		i, ok := s.index(args[0])
		if !ok {
			return
		}
		s.reply("+OK %d %d", i+1, msgs[i].Size)
		return
	}

	s.reply("+OK %d messages", len(msgs))
	for i, m := range msgs {
		s.reply("%d %d", i+1, m.Size)
	}
	s.reply(".")
}

func (s *session) retr(args []string) {
	if !s.requireTransaction() {
		return
	}
	if len(args) != 1 {
		s.reply("-ERR RETR requires a message number")
		return
	}
	i, ok := s.index(args[0])
	if !ok {
		return
	}
	s.reply("+OK %d octets", s.box.Messages()[i].Size)
	s.stream(func(ctx context.Context, w io.Writer) error {
		return s.box.WriteMessage(ctx, i, w)
	})
}

func (s *session) top(args []string) {
	if !s.requireTransaction() {
		return
	}
	if len(args) != 2 {
		s.reply("-ERR TOP requires a message number and a line count")
		return
	}
	i, ok := s.index(args[0])
	if !ok {
		return
	}
	n, err := strconv.Atoi(args[1])
	if err != nil || n < 0 {
		s.reply("-ERR invalid line count")
		return
	}
	s.reply("+OK")
	s.stream(func(ctx context.Context, w io.Writer) error {
		return s.box.WriteTop(ctx, i, n, w)
	})
}

// stream writes a multi-line response body, dot-encoded.
//
// net/textproto's DotWriter does the encoding the protocol requires: a line of the message that
// begins with "." is sent as ".." so the client does not read it as the terminator, and Close
// writes the final ".\r\n". Hand-rolling this is how a message containing a lone "." on a line
// silently truncates a session.
//
// A failure mid-body cannot be reported: the "+OK" is already on the wire and the client is
// reading a message, so there is no place left to put an error. The connection is dropped
// instead, which the client sees as an incomplete transfer and retries — better than a truncated
// message it would accept as whole.
func (s *session) stream(write func(context.Context, io.Writer) error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.srv.cfg.Timeout)
	defer cancel()

	_ = s.conn.SetWriteDeadline(nowAdd(s.srv.cfg.Timeout))
	dw := textproto.NewWriter(bufio.NewWriter(s.conn)).DotWriter()

	if err := write(ctx, dw); err != nil {
		_ = dw.Close()
		s.log("streaming body failed: %v", err)
		_ = s.conn.Close()
		return
	}
	if err := dw.Close(); err != nil {
		s.log("closing body failed: %v", err)
		_ = s.conn.Close()
	}
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
