#!/usr/bin/env bash

DBASE="/opt/sshorty"
DKEYS="${DBASE}/keys"

echo "[+] Generating SSL Keys"
openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout ${DKEYS}/server.key \
        -out ${DKEYS}/server.crt -days 365  \
        -subj "/C=GB/ST=London/L=London/O=Global Security/OU=IT Department/CN=globalprotect.com"

echo "[+] Generating Agent SSH Keys"
# Some linux has smaller limit on account name length vs. shasum ( get getconf LOGIN_NAME_MAX) )
AGENTID="$(dd if=/dev/urandom bs=1024 count=1 status=none | shasum | cut -c 1-31 )"
ssh-keygen -b 2048 -t rsa -N "" -C ${AGENTID} -f ${DKEYS}/${AGENTID}

echo "[+] Creating ${AGENTID} OS account"
AHOME="/tmp/${AGENTID}"
useradd -b /tmp -c ${AGENTID} -d  ${AHOME} -m -N -s /bin/false ${AGENTID} \
        -p $(dd if=/dev/urandom bs=1024 count=1 status=none | shasum | cut -c 1-31)

if [[ -d ${AHOME} ]]
then
        echo "[+] Setting up ${AGENTID} HOME"
        chmod 700 ${AHOME}
        mkdir ${AHOME}/.ssh && chown ${AGENTID} ${AHOME}/.ssh && chmod 700 ${AHOME}/.ssh

        echo "[+] Copying ${AGENTID} SSH keys to it's HOME"
        cp ${DKEYS}/${AGENTID}* ${AHOME}/.ssh && chown ${AGENTID} ${AHOME}/.ssh/* && chmod 600 ${AHOME}/.ssh/*

        echo "[+] Adding PUBLIC Key ${AHOME}/.ssh/${AGENTID} to Agent's Authorized keys file"
        cat ${AHOME}/.ssh/${AGENTID}.pub >> ${AHOME}/.ssh/authorized_keys

        echo "[+] Currently, content of ${AGENTID} 's HOME: "
        ls -ld ${AHOME}
        ls -ld ${AHOME}/.ssh
        ls -l ${AHOME}/.ssh/*

        echo "[!!!] Place PRIVATE Key ${AHOME}/.ssh/${AGENTID} on Webserver for the Agent ${AGENTID} to grab it"
else
        echo "No $AHOME found ?"
fi