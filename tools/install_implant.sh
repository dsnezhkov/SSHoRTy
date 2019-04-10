#!/bin/bash

#
#
# Build assumes Linux infra
#
#
#
usage(){
   echo "$0 /path/<implant>.tar.gz"
   exit 1
}

AGENT_PKG=""
AGENTID=""
AHOME_DIR="/tmp/"

if [[ $# -ne 1 ]]
then
   usage
fi

if [[ -f $1 ]]
then
   AGENT_PKG=$1
   _t=$(/usr/bin/basename -- "${AGENT_PKG}")
   AGENTID="${_t%.*.*}"
else 
	usage
fi

echo "[+] Checking if ${AGENTID} OS account is available"
/usr/bin/getent passwd $AGENTID >/dev/null

if [[ $? -eq 0 ]]
then
   echo "User account is already present. Investigate. Halting"
   exit 3
fi

echo "[+] Creating ${AGENTID} OS account"
AHOME="${AHOME_DIR}/${AGENTID}"

/usr/sbin/useradd  -c ${AGENTID} -d ${AHOME} -m -N -s /bin/false ${AGENTID} \
	-p $(dd if=/dev/urandom bs=1024 count=1 status=none | shasum | cut -c 1-31) # Throwaway password

if [[ -d ${AHOME} ]]
then
    cd  ${AHOME}
	echo "[+] Setting up ${AGENTID} HOME"
	chmod 700 ${AHOME} 
	mkdir ${AHOME}/.ssh && chown ${AGENTID} ${AHOME}/.ssh && chmod 700 ${AHOME}/.ssh

	echo "[+] Unpacking SSH Keys from ${AGENTID}.tar.gz"
    /bin/tar -xvzf ${AGENT_PKG} -C  ${AHOME}/.ssh

	echo "[+] Setting ${AGENTID} SSH keys"
	chown ${AGENTID} ${AHOME}/.ssh/${AGENTID}.{pk,pub,bpk} && chmod 600 ${AHOME}/.ssh/${AGENTID}.{pk,pub,bpk}

	echo "[+] Adding PUBLIC Key ${AHOME}/.ssh/${AGENTID} to Agent's Authorized keys file"
	cat ${AHOME}/.ssh/${AGENTID}.pub > ${AHOME}/.ssh/authorized_keys
	chown ${AGENTID} ${AHOME}/.ssh/authorized_keys

	echo "[+] Currently, content of ${AGENTID} 's HOME: "
	ls -ld ${AHOME}
	ls -ld ${AHOME}/.ssh
	ls -l ${AHOME}/.ssh/*

    cd -
	echo "[!!!] If not embedding PK into implant, host armored PK: ${AHOME}/.ssh/${AGENTID}.bpk "
else
	echo "No ${AHOME} found ?"
fi
