package main

import "sync"

// Global vars
var connections = new(sync.WaitGroup)

// LD_FLAGS' modifiable constants
var (
	serverHost      string //server host
	serverPort      string //server port
	serverUser      string //server user, logging in to server SSH

	remoteCmdHost   string //remote host
	remoteCmdPort   string //remote port
	remoteCmdUser   string //user logging in on reverse SSH shell, addt'l control
	remoteCmdPwd    string //pw for the ^^ user

	localHost       string //local host
	localPort       string //local port

	remoteSocksHost string //SOCKS host
	remoteSocksPort string //SOCKS port


	serverUserKeyUrl 		string // Where encrypted RSA key for SSH tunnel lives
	serverUserKeyPassphrase string // decryption key for ^^

)

// local service to be forwarded
var localEndpoint = Endpoint{
	Host: localHost,
	Port: localPort,
}

// remote SSH server
var serverEndpoint = Endpoint{
	Host: serverHost, //"192.168.88.15",
	Port: serverPort,
}

// remote reverse forwarding port for shell (on remote SSH server network)
var remoteEndpoint = Endpoint{
	Host: remoteCmdHost,
	Port: remoteCmdPort,
}

// remote reverse forwarding port for SOCKS (on remote SSH server network)
var remoteEndpointSOCKS = Endpoint{
	Host: remoteSocksHost,
	Port: remoteSocksPort,
}
