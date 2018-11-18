package main

import (
	"bufio"
	"fmt"
	"github.com/c-bata/go-prompt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/crypto/ssh"
)

var LivePrefixState struct {
	LivePrefix string
	IsEnable   bool
}
var commands = map[string]string{
	"#help": "Help",
	"#config": "Show configuration",
	"#shell": "Interactive host shell",
	"#quit": "To exit prompter",
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

		pin := prompt.Input(">>> ", completer,
			prompt.OptionTitle("agent controller"),
			prompt.OptionPrefixTextColor(prompt.Yellow),
			prompt.OptionPreviewSuggestionTextColor(prompt.Blue),
			prompt.OptionSelectedSuggestionBGColor(prompt.LightGray),
			prompt.OptionSuggestionBGColor(prompt.DarkGray),
			prompt.OptionLivePrefix(changeLivePrefix),
		)

		matchedACmd, _ := regexp.MatchString("#.*", pin)
		matchedHCmd, _ := regexp.MatchString("!.*", pin)

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

			if acmd == "shell" {
				execInSession("", conn, true)
			}
			if acmd == "quit" {
				return
			}

		}
		if matchedHCmd {
			hcmd := pin[1:]
			execInSession(hcmd, conn, false)
		}

	}

}

func execInSession(hcmd string, conn *ssh.Client, shell bool){

	session, err := conn.NewSession()
	if err != nil {
		log.Print("Failed to create session: " + err.Error())
	}
	defer session.Close()

	// Set IO
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	// stdin, _ := session.StdinPipe()
	//stdout, _ := session.StdoutPipe()


	var modes ssh.TerminalModes
	modes = ssh.TerminalModes{
		ssh.ECHO:          1,    // please print what I type
		ssh.ECHOCTL:       0,    // please don't print control chars
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	if shell {

		// Setup signal ignore or Ctrl+C breaks out of the client
		signalChannel := make(chan os.Signal, 2)
		signal.Notify(signalChannel, os.Interrupt, syscall.SIGINT)
		go func() {
			sig := <-signalChannel
			switch sig {
			case os.Interrupt:
				fmt.Print("os.Interrupt")
			case syscall.SIGINT:
				fmt.Print("SIGINT")
			default:
				fmt.Printf("%v",sig )
			}
		}()
	}

	var w, h int
	termFD := int(os.Stdin.Fd())

	if terminal.IsTerminal(termFD) {
		termState, _ := terminal.MakeRaw(termFD) // needed for vi and Interrupts
		defer terminal.Restore(termFD, termState)
		w, h, _ = terminal.GetSize(termFD)

		// Request pseudo terminal
		if err := session.RequestPty("xterm", h, w, modes); err != nil {
			log.Fatalf("request for pseudo terminal failed: %s", err)
		}
	}


	if shell {

		session.Setenv("LS_COLORS", os.Getenv("LS_COLORS"))
		session.Setenv("VISUAL", os.Getenv("VISUAL"))
		session.Setenv("EDITOR", os.Getenv("EDITOR"))
		session.Setenv("LANG", os.Getenv("LANG"))

		if err := session.Shell(); err != nil {
			log.Fatalf("Unable to execute shell: %v", err)
		}

		// monitor for sigwinch
		go monWinCh(session, termFD)


		if err := session.Wait(); err != nil {
			log.Fatalf("Remote command did not exit cleanly: %v", err)
		}


	}else{
		if err = session.Run(hcmd); err != nil {
			fmt.Fprintf(os.Stdout, "%v\n", err)
		}
	}


}


func monWinCh(session *ssh.Session, fd int) {
	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, syscall.SIGWINCH)
	defer signal.Stop(sigs)

	type resizeMessage struct {
		Width       uint32
		Height      uint32
		PixelWidth  uint32
		PixelHeight uint32
	}

	// resize the tty if any signals received
	for range sigs {

		width, height, _ := terminal.GetSize(fd)
		message := resizeMessage{
			Width:  uint32(width),
			Height: uint32(height),
		}
		session.SendRequest("window-change", false, ssh.Marshal(message))
	}
}



func helpCmd(){

	fmt.Printf("Agent commands start with `#`. Ex: #config\n")
	fmt.Printf("Host commands start with `!`. Ex: !ls\n")
	fmt.Printf("WARNING: Host commands do not support signals. If you need full shell. execute #shell\n")
	fmt.Print("\nAgent commands:\n")
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


