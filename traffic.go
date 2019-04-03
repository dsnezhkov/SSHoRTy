package main

import (
	"fmt"
	"github.com/kr/pty"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

// Listens for SSH connection
func listenConnection(client net.Conn, config *ssh.ServerConfig) {

	// Before use, a handshake must be performed on the incoming net.Conn.
	sshConn, chans, reqs, err := ssh.NewServerConn(client, config)
	if err != nil {
		log.Printf("Failed to handshake (%s)", err)
		return
	}

	log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

	// Discard all irrelevant incoming request but serve the one you really need to care.
	// DiscardRequests consumes and rejects all requests from the
	// passed-in channel.

	//       go ssh.DiscardRequests(reqs)
	go handleRequests(reqs)
	// Accept all channels
	go handleChannels(chans)

}

func listenSConnection(SClientConn net.Conn) {
	go handleSConn(SClientConn)
}

func acceptLoop(listener net.Listener, config *ssh.ServerConfig) {
	log.Printf("Listener: %s\n", listener.Addr().String())
	defer listener.Close()
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("New connection found on %s\n", listener.Addr().String())
		go listenConnection(clientConn, config)
	}
}

func acceptSLoop(listener net.Listener) {

	log.Printf("Listener: %s\n", listener.Addr().String())
	defer listener.Close()
	for {
		clientConn, err := listener.Accept()
		log.Printf("local addr %s\n", clientConn.LocalAddr())
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("New connection found on %s\n", listener.Addr().String())

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
		// TODO: other types of channels (x11, forwarded-tcp, direct-tcp) may need to be handled here
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
			shell = "/bin/sh" // Default
		}

		// Sessions have out-of-band requests such as "exec", "shell", "pty-req" and "env"
		go func(in <-chan *ssh.Request) {
			for req := range in {
				// log.Printf("%v %s", req.Payload, req.Payload)
				ok := false
				switch req.Type {
				case "exec":
					ok = true
					command := string(req.Payload[4 : req.Payload[3]+4])

					// Start Command via shell
					// TODO: maybe without shell?
					cmd := exec.Command(shell, []string{"-c", command}...)
					log.Printf("cmd to exec: %s\n", command)

					cmd.Stdout = channel
					cmd.Stderr = channel
					cmd.Stdin = channel

					err := cmd.Start()
					if err != nil {
						log.Printf("could not start command (%s)", err)
						continue
					}

					// Teardown session
					go func() {
						_, err := cmd.Process.Wait()
						if err != nil {
							log.Printf("failed to exit bash (%s)", err)
						}
						channel.Close()
						log.Printf("session closed")
					}()
				case "shell":
					// TODO: parameterize shell and TERM
					cmd := exec.Command(shell)
					cmd.Env = []string{"TERM=xterm"} // is this a common default?
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

					//pipe session to bash and visa-versa
					go func() {
						_, err := io.Copy(channel, f)
						if err != nil {
							log.Println(fmt.Sprintf("error copy bash -> remote : %s", err))
						}
						once.Do(closeCh)
					}()
					go func() {
						_, err := io.Copy(f, channel)
						if err != nil {
							log.Println(fmt.Sprintf("error copy remote -> bash: %s", err))
						}
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
				case "subsystem":
					log.Printf("Subsystem: %s\n", req.Payload[4:])
					subsystemId := string(req.Payload[4:])
					if subsystemId == "sftp" {

						debugStream := ioutil.Discard
						serverOptions := []sftp.ServerOption{
							sftp.WithDebug(debugStream),
						}

						server, err := sftp.NewServer(
							channel,
							serverOptions...,
						)
						if err != nil {
							log.Fatal(err)
						}
						if err := server.Serve(); err == io.EOF {
							server.Close()
							log.Print("sftp client exited session.")
						} else if err != nil {
							log.Fatal("sftp server completed with error:", err)
						}

						ok = true
					} else {
						// TODO: Implement `env` type of *ssh.Request
						log.Printf("Declining Subsystem: %s\n", subsystemId)
					}
				}

				if !ok {
					log.Printf("declining %s request...", req.Type)
				}

				req.Reply(ok, nil)
			}
		}(requests)
	}
}
