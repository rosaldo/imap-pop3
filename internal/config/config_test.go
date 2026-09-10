package config

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeCert produces a real, self-signed certificate pair on disk. The point is to exercise
// tls.LoadX509KeyPair for real rather than to trust a fixture that merely looks like PEM.
func writeCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func write(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "imap-pop3.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValidConfig(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeCert(t, dir)
	path := write(t, dir, `
listen: ":1995"
timeout: 5m
tls:
  cert: `+cert+`
  key: `+key+`
upstreams:
  example.org:
    host: imap.example.org:993
    mailbox: INBOX
`)

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Listen != ":1995" {
		t.Errorf("listen = %q", c.Listen)
	}
	if c.Timeout != 5*time.Minute {
		t.Errorf("timeout = %v", c.Timeout)
	}
	if up := c.Backend()["example.org"]; up.Host != "imap.example.org:993" {
		t.Errorf("upstream = %+v", up)
	}
	if _, err := c.TLSConfig(); err != nil {
		t.Errorf("TLSConfig: %v", err)
	}
}

func TestDefaults(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeCert(t, dir)
	path := write(t, dir, `
tls:
  cert: `+cert+`
  key: `+key+`
upstreams:
  example.org: {host: "imap.example.org:993"}
`)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Listen != defaultListen {
		t.Errorf("listen default = %q, want %q", c.Listen, defaultListen)
	}
	if c.Timeout != defaultTimeout {
		t.Errorf("timeout default = %v, want %v", c.Timeout, defaultTimeout)
	}
}

// TestRefusesToStart covers every configuration that must stop the process instead of producing
// a server that looks healthy.
func TestRefusesToStart(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeCert(t, dir)

	cases := []struct {
		name, body, wantErr string
	}{
		{
			name:    "no TLS at all",
			body:    "upstreams:\n  example.org: {host: \"imap.example.org:993\"}\n",
			wantErr: "will not serve POP3 in the clear",
		},
		{
			// `tls.key` is optional — the key may live inside the certificate file. This one
			// does NOT, so it still has to be refused, and the message has to say where the
			// key was looked for instead of blaming the PEM.
			name:    "certificate without key, and none inside it",
			body:    "tls:\n  cert: " + cert + "\nupstreams:\n  example.org: {host: \"x:993\"}\n",
			wantErr: "the key was looked for inside",
		},
		{
			name:    "certificate that does not load",
			body:    "tls:\n  cert: " + dir + "/missing.pem\n  key: " + key + "\nupstreams:\n  example.org: {host: \"x:993\"}\n",
			wantErr: "loading the TLS certificate",
		},
		{
			name:    "no upstreams",
			body:    "tls:\n  cert: " + cert + "\n  key: " + key + "\nupstreams: {}\n",
			wantErr: "no upstreams configured",
		},
		{
			name:    "upstream without a port",
			body:    "tls:\n  cert: " + cert + "\n  key: " + key + "\nupstreams:\n  example.org: {host: \"imap.example.org\"}\n",
			wantErr: "needs a port",
		},
		{
			name:    "domain not lowercase",
			body:    "tls:\n  cert: " + cert + "\n  key: " + key + "\nupstreams:\n  Example.ORG: {host: \"x:993\"}\n",
			wantErr: "must be lowercase",
		},
		{
			name:    "misspelled key",
			body:    "tls:\n  cert: " + cert + "\n  key: " + key + "\nupstream:\n  example.org: {host: \"x:993\"}\n",
			wantErr: "parsing",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := write(t, t.TempDir(), tc.body)
			_, err := Load(path)
			if err == nil {
				t.Fatalf("Load succeeded — the server would have started")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("Load succeeded on a file that does not exist")
	}
}

// writeCombinedPEM writes ONE file holding the private key and the certificate, in the order an
// ACME client writes it: key first, then the leaf, then the chain. Built from a real key pair,
// not a fixture that merely looks like PEM — the point is to exercise tls.LoadX509KeyPair.
func writeCombinedPEM(t *testing.T, dir string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "mail.example.org"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatal(err)
	}
	// Twice: the leaf and one more standing in for the chain. A single-certificate file would
	// pass even if the loader stopped at the first block.
	for range 2 {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "combined.pem")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestKeyInsideTheCertificateFile: `tls.key` may be omitted when the certificate file already
// carries the key — the shape every ACME client that manages its own certificates writes, mox
// included. Requiring two files forces whoever deploys next to such a server to copy and split
// that file, and the copy goes stale at the first renewal: sixty days later the renewed
// certificate is on disk and the adapter still serves the expired one.
func TestKeyInsideTheCertificateFile(t *testing.T) {
	dir := t.TempDir()
	combined := writeCombinedPEM(t, dir)
	body := "tls:\n  cert: " + combined + "\nupstreams:\n  example.org: {host: \"imap.example.org:993\"}\n"

	cfg, err := Load(write(t, dir, body))
	if err != nil {
		t.Fatalf("a PEM holding the key and the chain was refused: %v", err)
	}
	tlsCfg, err := cfg.TLSConfig()
	if err != nil {
		t.Fatalf("TLSConfig: %v", err)
	}
	if n := len(tlsCfg.Certificates); n != 1 {
		t.Fatalf("expected one certificate, got %d", n)
	}
	// The whole chain has to survive: serving only the leaf makes a client without the
	// intermediate reject a certificate that is perfectly valid.
	if n := len(tlsCfg.Certificates[0].Certificate); n != 2 {
		t.Errorf("the chain lost blocks: %d certificates, expected 2", n)
	}
	if tlsCfg.Certificates[0].PrivateKey == nil {
		t.Error("no private key was loaded — the key inside the certificate file was ignored")
	}
}
