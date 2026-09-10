// Package config loads and validates the operator's file.
package config

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rosaldo/imap-pop3/internal/imapbackend"
)

// Config is the whole file.
type Config struct {
	// Listen is the address to serve POP3 on. 995 is the implicit-TLS port.
	Listen string `yaml:"listen"`
	// TLS is required. There is no plaintext mode — see Validate.
	TLS TLS `yaml:"tls"`
	// Timeout bounds a single client command.
	Timeout time.Duration `yaml:"timeout"`
	// Upstreams maps a username's domain to the IMAP server that serves it.
	Upstreams map[string]Upstream `yaml:"upstreams"`
}

type TLS struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type Upstream struct {
	Host    string `yaml:"host"`
	Mailbox string `yaml:"mailbox"`
}

const (
	defaultListen  = ":995"
	defaultTimeout = 10 * time.Minute
)

// Load reads and validates the file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var c Config
	// KnownFields makes a typo in a key an error instead of a silently ignored line. A
	// misspelled "upstream:" would otherwise leave the map empty and look like a server bug.
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	if c.Listen == "" {
		c.Listen = defaultListen
	}
	if c.Timeout <= 0 {
		c.Timeout = defaultTimeout
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate refuses a configuration that would start a server nobody should be running.
func (c *Config) Validate() error {
	// No plaintext fallback, on purpose. This server carries someone's mailbox password to a
	// remote IMAP server; a missing certificate is a reason to stop, never a reason to serve
	// the same thing in the clear.
	if c.TLS.Cert == "" {
		return fmt.Errorf("tls.cert is required — this server will not serve POP3 in the clear")
	}
	if _, err := tls.LoadX509KeyPair(c.TLS.Cert, c.keyPath()); err != nil {
		// Say WHERE the key was looked for. With `tls.key` omitted the key is expected inside
		// the certificate file, and Go's own message for that case ("found a certificate
		// rather than a key in the PEM for the private key") reads like a corrupt file to
		// someone who simply forgot the field.
		if c.TLS.Key == "" {
			return fmt.Errorf("loading the TLS certificate: %w — tls.key is not set, so the key was "+
				"looked for inside %s; set tls.key, or point tls.cert at a PEM that holds the key "+
				"and the chain together", err, c.TLS.Cert)
		}
		return fmt.Errorf("loading the TLS certificate: %w", err)
	}

	// An empty map means every login is refused. Better to say so at boot than to look healthy
	// and turn away every user.
	if len(c.Upstreams) == 0 {
		return fmt.Errorf("no upstreams configured — every login would be refused")
	}
	for domain, up := range c.Upstreams {
		if domain != strings.ToLower(domain) {
			return fmt.Errorf("upstream domain %q must be lowercase", domain)
		}
		if up.Host == "" {
			return fmt.Errorf("upstream %q has no host", domain)
		}
		if !strings.Contains(up.Host, ":") {
			return fmt.Errorf("upstream %q host %q needs a port, e.g. %s:993", domain, up.Host, up.Host)
		}
	}
	return nil
}

// Backend converts the upstream map into what imapbackend expects.
func (c *Config) Backend() map[string]imapbackend.Upstream {
	out := make(map[string]imapbackend.Upstream, len(c.Upstreams))
	for domain, up := range c.Upstreams {
		out[domain] = imapbackend.Upstream{Host: up.Host, Mailbox: up.Mailbox}
	}
	return out
}

// keyPath says where the private key lives: the file configured as `tls.key`, or the
// certificate file itself when that field is absent.
//
// A SINGLE FILE HOLDING BOTH IS A REAL FORMAT, not a convenience. ACME clients that manage
// their own certificates — mox among them — keep the key and the whole chain concatenated in
// one PEM, and refreshing it in place is how renewal works there. Demanding two files forced
// whoever deployed this adapter next to such a server to copy and split that file on every
// deploy, and a copy of a certificate is a copy that goes stale: sixty days later the renewed
// certificate is on disk and the adapter is still serving the expired one.
//
// It works because `tls.LoadX509KeyPair` reads both arguments independently and skips the PEM
// blocks it is not looking for: given the same path twice, the first read collects the
// certificate chain and the second finds the key among them. The leaf must come first in the
// file, which is what every ACME client writes.
func (c *Config) keyPath() string {
	if c.TLS.Key != "" {
		return c.TLS.Key
	}
	return c.TLS.Cert
}

// TLSConfig builds the server's TLS configuration. Validate has already proved the pair loads.
func (c *Config) TLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(c.TLS.Cert, c.keyPath())
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}
