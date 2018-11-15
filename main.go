package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/c-bata/go-prompt"
	"golang.org/x/crypto/ssh"
)

func main() {

	// config
	config := &ssh.ClientConfig{
		User: "postgres",
		Auth: []ssh.AuthMethod{
			ssh.Password("Drg4r1c3"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// connect
	client, err := ssh.Dial("tcp", "192.168.88.15:22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// start session
	session, err := client.NewSession()
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	// hook up standard out & standard error
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	// create a pipe so we can write to stdin
	stdin, err := session.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO: 0, // Disable echoing
		//ssh.IGNCR: 1, // Ignore CR on input.
	}
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		log.Fatalf("request for pseudo terminal failed: %s", err)
	}

	if err := session.Shell(); err != nil {
		log.Fatalf("failed to start shell: %s", err)
	}

	/*
		// start bash
		if err := session.Start("/bin/bash"); err != nil {
			log.Fatal(err)
		}
	*/

	// send the commands
	/*
		commands := []string{
			"ls",
			"whoami",
			"echo 'hello world'",
			"exit",
		}
		for _, cmd := range commands {
			if _, err = fmt.Fprintf(stdin, "%s\n", cmd); err != nil {
				log.Fatal(err)
			}
		}*/

	for {

		t := prompt.Input("> ", completer)
		cmd := strings.TrimSpace(t)
		if cmd == "quit" || cmd == "exit" {
			fmt.Println("Bye!")
			os.Exit(0)
			break
		}

		fmt.Println("executing" + cmd)
		if _, err = fmt.Fprintf(stdin, "%s\n", cmd); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(stdin, "\n")
	}

	// wait for process to finish
	if err := session.Wait(); err != nil {
		log.Fatal(err)
	}
}

func completer(d prompt.Document) []prompt.Suggest {
	s := []prompt.Suggest{
		{Text: "ls", Description: "List files"},
		{Text: "whoami", Description: "Announce yourself"},
		{Text: "echo", Description: "Say something"},
	}
	return prompt.FilterHasPrefix(s, d.GetWordBeforeCursor(), true)
}
