// Command imap-pop3 serves an IMAP mailbox over POP3.
//
// It owns no mailbox: every POP3 command is answered by talking to an IMAP server upstream, and
// the credentials presented over POP3 are the ones used to authenticate there. Nothing is stored.
package main

import (
	"flag"
	"fmt"
	"os"
)

// version is stamped at build time by scripts/push.sh, with
// -ldflags "-X main.version=<VERSION>". A plain `go build` leaves it as "dev", which is a more
// honest answer than a number that was never released.
var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	fmt.Fprintf(os.Stderr, "imap-pop3 %s: no configuration yet\n", version)
	os.Exit(2)
}
