#!/usr/bin/env bash

DBASE="/opt/sshorty"
DKEYS="${DBASE}/keys"

echo "[+] Generating SSL Keys"
openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout ${DKEYS}/server.key \
        -out ${DKEYS}/server.crt -days 365  \
        -subj "/C=GB/ST=London/L=London/O=Global Security/OU=IT Department/CN=globalprotect.com"

