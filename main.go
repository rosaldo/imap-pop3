// Command imap-pop3 serves an IMAP mailbox over POP3.
//
// It owns no mailbox: every POP3 command is answered by talking to an IMAP server upstream, and
// the credentials presented over POP3 are the ones used to authenticate there. Nothing is stored.
package main

import "fmt"

func main() {
	fmt.Println("imap-pop3")
}
