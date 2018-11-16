package main

import (
	"fmt"
	"github.com/kr/pty"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

func listenConnection(client net.Conn, config *ssh.ServerConfig) {
	// Before use, a handshake must be performed on the incoming net.Conn.
	sshConn, chans, reqs, err := ssh.NewServerConn(client, config)
	if err != nil {
		log.Printf("Failed to handshake (%s)", err)
		return
	}

	log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

	// Discard all irrelevant incoming request but serve the one you really need to care.
	// go ssh.DiscardRequests(reqs)
	go handleRequests(reqs)
	// Accept all channels
	go handleChannels(chans)

}
func listenSConnection(SClientConn net.Conn) {

	go handleSConn(SClientConn)

}
func acceptLoop(listener net.Listener, config *ssh.ServerConfig) {
	fmt.Printf("Listener: %s\n", listener.Addr().String())
	defer listener.Close()
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("New connection found on %s\n", listener.Addr().String())
		go listenConnection(clientConn, config)
	}
}

func acceptSLoop(listener net.Listener) {

	fmt.Printf("Listener: %s\n", listener.Addr().String())
	defer listener.Close()
	for {
		clientConn, err := listener.Accept()
		fmt.Printf("local addr %s\n", clientConn.LocalAddr())
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("New connection found on %s\n", listener.Addr().String())

		go listenSConnection(clientConn)
	}

	log.Println("waiting for all existing connections to finish")
	connections.Wait()
	log.Println("shutting down")
}

func handleRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		log.Printf("recieved out-of-band request: %+v", req)
	}
}

// Start assigns a pseudo-terminal tty os.File to c.Stdin, c.Stdout,
// and c.Stderr, calls c.Start, and returns the File of the tty's
// corresponding pty.
func PtyRun(c *exec.Cmd, tty *os.File) (err error) {
	defer tty.Close()
	c.Stdout = tty
	c.Stdin = tty
	c.Stderr = tty
	c.SysProcAttr = &syscall.SysProcAttr{
		Setctty: true,
		Setsid:  true,
	}
	return c.Start()
}

func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if t := newChannel.ChannelType(); t != "session" {
			newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("could not accept channel (%s)", err)
			continue
		}

		// allocate a terminal for this channel
		log.Print("creating pty...")
		// Create new pty
		f, tty, err := pty.Open()
		if err != nil {
			log.Printf("could not start pty (%s)", err)
			continue
		}

		var shell string
		shell = os.Getenv("SHELL")
		if shell == "" {
			shell = "bash"
		}

		// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
		go func(in <-chan *ssh.Request) {
			for req := range in {
				log.Printf("%v %s", req.Payload, req.Payload)
				ok := false
				switch req.Type {
				case "exec":
					ok = true
					command := string(req.Payload[4 : req.Payload[3]+4])
					cmd := exec.Command(shell, []string{"-c", command}...)

					cmd.Stdout = channel
					cmd.Stderr = channel
					cmd.Stdin = channel

					err := cmd.Start()
					if err != nil {
						log.Printf("could not start command (%s)", err)
						continue
					}

					// teardown session
					go func() {
						_, err := cmd.Process.Wait()
						if err != nil {
							log.Printf("failed to exit bash (%s)", err)
						}
						channel.Close()
						log.Printf("session closed")
					}()
				case "shell":
					cmd := exec.Command(shell)
					cmd.Env = []string{"TERM=xterm"}
					err := PtyRun(cmd, tty)
					if err != nil {
						log.Printf("%s", err)
					}

					// Teardown session
					var once sync.Once
					closeCh := func() {
						channel.Close()
						log.Printf("session closed")
					}

					// Pipe session to bash and visa-versa
					go func() {
						io.Copy(channel, f)
						once.Do(closeCh)
					}()

					go func() {
						io.Copy(f, channel)
						once.Do(closeCh)
					}()

					// We don't accept any commands (Payload),
					// only the default shell.
					if len(req.Payload) == 0 {
						ok = true
					}
				case "pty-req":
					// Responding 'ok' here will let the client
					// know we have a pty ready for input
					ok = true
					// Parse body...
					termLen := req.Payload[3]
					termEnv := string(req.Payload[4 : termLen+4])
					w, h := parseDims(req.Payload[termLen+4:])
					SetWinsize(f.Fd(), w, h)
					log.Printf("pty-req '%s'", termEnv)
				case "window-change":
					w, h := parseDims(req.Payload)
					SetWinsize(f.Fd(), w, h)
					continue //no response
				}

				if !ok {
					log.Printf("declining %s request...", req.Type)
				}

				req.Reply(ok, nil)
			}
		}(requests)
	}
}

// =======================


/*func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		// We need to accept requests from current channel, and serve them in separate goroutines so the connection won’t be blocked.
		go handleChannel(newChannel)
	}
}

func handleChannel(newChannel ssh.NewChannel) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}


	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}


	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		for req := range requests {

			bashf := os.File{}
			log.Printf("Req type: %s payload %s", req.Type, req.Payload)
			switch req.Type {
			case "exec":
				cmdName := strings.Trim(string(req.Payload), "'()")
				log.Printf("Command %s", cmdName)
			case "shell":
				bashf = launchInteractive(connection)
				// We only accept the default shell
				// (i.e. no command in the Payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)
				}
			case "pty-req":
				if (os.File{}) != bashf {
					termLen := req.Payload[3]
					w, h := parseDims(req.Payload[termLen+4:])
					SetWinsize(bashf.Fd(), w, h)
					// Responding true (OK) here will let the client
					// know we have a pty ready for input
				}else{
					bashf = launchInteractive(connection)
					termLen := req.Payload[3]
					w, h := parseDims(req.Payload[termLen+4:])
					SetWinsize(bashf.Fd(), w, h)
				}
				req.Reply(true, nil)
			case "window-change":
				w, h := parseDims(req.Payload)
				SetWinsize(bashf.Fd(), w, h)
			}
		}
	}()
}
*/
// =======================


// in - local SOCKS conn, out - remote desired endpoint
func transfer(in, out net.Conn) {
	wg := new(sync.WaitGroup)
	wg.Add(2)
	f := func(in, out net.Conn, wg *sync.WaitGroup) {

		// copy bytes verbatim
		n, err := io.Copy(out, in)
		log.Printf("xfer done: in=%v\tout=%v\ttransfered=%d\terr=%v", in.RemoteAddr(), out.RemoteAddr(), n, err)
		// close write side on local SOCKS
		if conn, ok := in.(*net.TCPConn); ok {
			conn.CloseWrite()
		}
		// close read side to remote endpoint
		if conn, ok := out.(*net.TCPConn); ok {
			conn.CloseRead()
		}
		wg.Done()
	}
	go f(in, out, wg)
	f(out, in, wg)
	wg.Wait()
	out.Close()
}

/*
func launchInteractive(connection ssh.Channel)  (ptmx os.File) {

	// Fire up bash for this session
	bash := exec.Command("bash")

	// Prepare teardown function
	closeConn := func() {
		connection.Close()
		_, err := bash.Process.Wait()
		if err != nil {
			log.Printf("Failed to exit bash (%s)", err)
		}
		log.Printf("Session closed")
	}

	// Allocate a terminal for this channel
	log.Print("Creating ppty...")
	bashf, err := pty.Start(bash)
	if err != nil {
		log.Printf("Could not start pty (%s)", err)
		closeConn()
		return
	}

	//pipe session to bash and visa-versa
	var once sync.Once
	go func() {
		_, err := io.Copy(connection, bashf)
		if err != nil {
			log.Println(fmt.Sprintf("error while copy bash -> remote : %s", err))
		}
		once.Do(closeConn)
	}()
	go func() {
		_, err := io.Copy(bashf, connection)
		if err != nil {
			log.Println(fmt.Sprintf("error while copy remote -> bash: %s", err))
		}
		once.Do(closeConn)
	}()

	return *bashf
}

*/
/*func handleClient(client net.Conn, remote net.Conn) {
	defer client.Close()
	chDone := make(chan bool)

	// Start remote -> local data transfer
	go func() {
		_, err := io.Copy(client, remote)
		if err != nil {
			log.Println(fmt.Sprintf("error while copy remote->local: %s", err))
		}
		chDone <- true
	}()

	// Start local -> remote data transfer
	go func() {
		_, err := io.Copy(remote, client)
		if err != nil {
			log.Println(fmt.Sprintf("error while copy local->remote: %s", err))
		}
		chDone <- true
	}()

	<-chDone
}*/
