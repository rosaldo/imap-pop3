// Command imap-pop3 serves an IMAP mailbox over POP3.
//
// It owns no mailbox: every POP3 command is answered by talking to an IMAP server upstream, and
// the credentials presented over POP3 are the ones used to authenticate there. Nothing is stored.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rosaldo/imap-pop3/internal/config"
	"github.com/rosaldo/imap-pop3/internal/imapbackend"
	"github.com/rosaldo/imap-pop3/internal/pop3"
)

// version is stamped at build time by scripts/push.sh and by the release workflow, with
// -ldflags "-X main.version=<VERSION>". A plain `go build` leaves it as "dev", which is a more
// honest answer than a number that was never released.
var version = "dev"

func main() {
	configPath := flag.String("config", "imap-pop3.yaml", "path to the configuration file")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	if err := run(*configPath); err != nil {
		fmt.Fprintln(os.Stderr, "imap-pop3:", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	logger := slog.Default()

	backend := imapbackend.New(imapbackend.Config{
		Upstreams: cfg.Backend(),
		Logger:    logger,
	})
	srv := pop3.New(backend, pop3.Config{Timeout: cfg.Timeout, Logger: logger})

	tlsCfg, err := cfg.TLSConfig()
	if err != nil {
		return err
	}
	// Implicit TLS, the whole session encrypted from the first byte — not STARTTLS, which opens
	// in the clear and adds a command whose absence a client may not notice.
	ln, err := tls.Listen("tcp", cfg.Listen, tlsCfg)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", cfg.Listen, err)
	}

	// Shutdown is wired before Serve so a signal arriving during startup is still honoured.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Warn("shutdown did not finish cleanly", "err", err)
		}
	}()

	logger.Info("serving POP3 over TLS",
		"version", version,
		"listen", cfg.Listen,
		"upstreams", len(cfg.Upstreams))

	if err := srv.Serve(ln); err != nil && !isClosed(err) {
		return fmt.Errorf("serving: %w", err)
	}
	return nil
}

func isClosed(err error) bool {
	return err == net.ErrClosed
}
