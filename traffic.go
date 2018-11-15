package main

import (
	"fmt"
	"github.com/kr/pty"
	"io"
	"log"
	"net"
	"os/exec"
	"sync"
	"golang.org/x/crypto/ssh"
)

func listenConnection(client net.Conn, config *ssh.ServerConfig) {
	// Before use, a handshake must be performed on the incoming net.Conn.
	sshConn, chans, reqs, err := ssh.NewServerConn(client, config)
	if err != nil {
		log.Printf("Failed to handshake (%s)", err)
		return
	}

	log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

	// Discard all global out-of-band Requests
	go ssh.DiscardRequests(reqs)
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

func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
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
	log.Print("Creating pty...")
	bashf, err := pty.Start(bash)
	if err != nil {
		log.Printf("Could not start pty (%s)", err)
		closeConn()
		return
	}

	//pipe session to bash and visa-versa
	var once sync.Once
	go func() {
		io.Copy(connection, bashf)
		once.Do(closeConn)
	}()
	go func() {
		io.Copy(bashf, connection)
		once.Do(closeConn)
	}()

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		for req := range requests {
			switch req.Type {
			case "shell":
				// We only accept the default shell
				// (i.e. no command in the Payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)
				}
			case "pty-req":
				termLen := req.Payload[3]
				w, h := parseDims(req.Payload[termLen+4:])
				SetWinsize(bashf.Fd(), w, h)
				// Responding true (OK) here will let the client
				// know we have a pty ready for input
				req.Reply(true, nil)
			case "window-change":
				w, h := parseDims(req.Payload)
				SetWinsize(bashf.Fd(), w, h)
			}
		}
	}()
}

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

func handleClient(client net.Conn, remote net.Conn) {
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
}
