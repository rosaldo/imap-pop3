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
	if c.TLS.Cert == "" || c.TLS.Key == "" {
		return fmt.Errorf("tls.cert and tls.key are required — this server will not serve POP3 in the clear")
	}
	if _, err := tls.LoadX509KeyPair(c.TLS.Cert, c.TLS.Key); err != nil {
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

// TLSConfig builds the server's TLS configuration. Validate has already proved the pair loads.
func (c *Config) TLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(c.TLS.Cert, c.TLS.Key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}
