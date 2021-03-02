package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	expect "github.com/google/goexpect"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	timeout = 10 * time.Minute
)

func hostNameCheck(u *url.URL) ssh.PublicKey {
	var key ssh.PublicKey
	var toMatch string

	if strings.Contains(u.Host, ":") {
		parts := strings.Split(u.Host, ":")
		toMatch = fmt.Sprintf("[%s]:%s", parts[0], parts[1])
	} else {
		toMatch = u.Host
	}

	kh, err := os.Open(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		return nil
	}
	defer kh.Close()

	scanner := bufio.NewScanner(kh)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), toMatch) {
			key, _, _, _, err = ssh.ParseAuthorizedKey(scanner.Bytes())
			if err != nil {
				return nil
			}
			break
		}
	}

	return key
}

func main() {

	if len(os.Args) == 1 {
		log.Fatalf("typie: ssh://user@host:port")
		os.Exit(1)
	}

	u, err := url.Parse(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		log.Fatalf("Failed to open SSH_AUTH_SOCK: %v", err)
	}

	agentClient := agent.NewClient(conn)
	config := &ssh.ClientConfig{
		User: u.User.String(),
		Auth: []ssh.AuthMethod{
			ssh.PublicKeysCallback(agentClient.Signers),
		},
		HostKeyCallback: ssh.FixedHostKey(hostNameCheck(u)),
	}

	fmt.Print("Password to send: ")
	b, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatal(err)
	}
	pass := string(b)
	fmt.Println()

	sshClient, err := ssh.Dial("tcp", u.Host, config)
	if err != nil {
		log.Fatalf("ssh.Dial(%q) failed: %v", u.Host, err)
	}
	defer sshClient.Close()

	e, _, err := expect.SpawnSSH(sshClient, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer e.Close()

	log.Println("Watching...")
	for {
		_, err := e.ExpectBatch([]expect.Batcher{
			&expect.BExp{R: "Passphrase: "},
			&expect.BSnd{S: fmt.Sprintf("%s\n", pass)},
			&expect.BExp{R: "boot>"},
			&expect.BSnd{S: "\n"},
		}, timeout)

		if err != nil {
			if err != expect.TimeoutError(timeout) {
				log.Fatal(err)
			}
		} else {
			log.Println("sent passphrase")
		}

		time.Sleep(3)
	}
}
