package main

import (
	"bufio"
	"fmt"
	"github.com/c-bata/go-prompt"
	"log"
	"os"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

var LivePrefixState struct {
	LivePrefix string
	IsEnable   bool
}
var commands = map[string]string{
	"#help": "Help",
	"#config": "Show configuration",
	"#quit": "exit prompter",
}

func main() {
	server := "192.168.88.15"
	port := "22"
	server = server + ":" + port
	user := "tester"
	p := "Drg4r1c3"

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			// ClientAuthPassword wraps a ClientPassword implementation
			// in a type that implements ClientAuth.
			ssh.Password(p),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	conn, err := ssh.Dial("tcp", server, config)
	if err != nil {
		panic("Failed to dial: " + err.Error())
	}
	defer conn.Close()

	for {
		// Each ClientConn can support multiple interactive sessions,
		// represented by a Session.
		session, err := conn.NewSession()
		if err != nil {
			log.Print("Failed to create session: " + err.Error())
			continue
		}
		defer session.Close()

		// Set IO
		session.Stdout = os.Stdout
		session.Stderr = os.Stderr
		in, _ := session.StdinPipe()

		// Set up terminal modes
		modes := ssh.TerminalModes{
			ssh.ECHO:          0,     // disable echoing
			ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
			ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
		}

		// Request pseudo terminal
		if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
			log.Fatalf("request for pseudo terminal failed: %s", err)
		}

		/*
		// Start remote shell
		if err := session.Shell(); err != nil {
			log.Fatalf("failed to start shell: %s", err)
		}
		*/


		pin := prompt.Input(">>> ", completer,
			prompt.OptionTitle("agent controller"),
			prompt.OptionPrefixTextColor(prompt.Yellow),
			prompt.OptionPreviewSuggestionTextColor(prompt.Blue),
			prompt.OptionSelectedSuggestionBGColor(prompt.LightGray),
			prompt.OptionSuggestionBGColor(prompt.DarkGray),
			prompt.OptionLivePrefix(changeLivePrefix),
		)


		matchedACmd, err := regexp.MatchString("#.*", pin)
		matchedHCmd, err := regexp.MatchString("!.*", pin)

		if ! (matchedACmd || matchedHCmd){

			fmt.Println("type `#help` for help")
		}
		if matchedACmd {
			acmd := pin[1:]

			if acmd == "" {
				LivePrefixState.IsEnable = false
				LivePrefixState.LivePrefix = acmd
			}

			if acmd == "config" {
				LivePrefixState.LivePrefix = acmd + "> "
				LivePrefixState.IsEnable = true
			}
			if acmd == "help" {
				LivePrefixState.IsEnable = false
				LivePrefixState.LivePrefix = acmd
				helpCmd()
			}

			if acmd == "quit" {
				return
			}

		}
		if matchedHCmd {
			hcmd := pin[1:]
			//var retBuff []byte
			//reader := bufio.NewReader(os.Stdin)
			//inBuff, _, _ := reader.ReadLine()
			if err = session.Run(hcmd); err != nil {
				fmt.Fprintf(in, "%v\n", err)
			}

			/*if _, err := reader.Read(retBuff); err != nil {
				fmt.Printf("%v\n", err.Error())
			}
			fmt.Fprint(in, retBuff)*/
		}

	}

}

func helpCmd(){

	fmt.Printf("Agent commands start with `#`. Ex: #config\n")
	fmt.Printf("Host commands start with `!`. Ex: !ls\n")
	fmt.Print("Agent commands:\n")
	for key, value := range commands{
		fmt.Printf("\t%-20s - %s\n", key, value)
	}
}
func getInput() string {
	input, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	input = strings.Trim(input, "\n")
	return input
}

func changeLivePrefix() (string, bool) {
	return LivePrefixState.LivePrefix, LivePrefixState.IsEnable
}

func completer(t prompt.Document) []prompt.Suggest {
	var s = []prompt.Suggest{}

	for key, value := range commands{
		s = append(s, prompt.Suggest{key,value})
	}

	return prompt.FilterHasPrefix(s, t.GetWordBeforeCursor(), true)
}


