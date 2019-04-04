#!/usr/bin/env bash

# DESTINATION_SSH_ADDR=167.99.88.24
DESTINATION_SSH_ADDR=127.0.0.1
DESTINATION_SSH_PORT=222
WSS_LPORT=8082
/opt/sshorty/websockify/websockify.py  --ssl-only --log-file=/opt/sshorty/logs/websocksify.log --cert=/opt/sshorty/keys/server.crt --key=/opt/sshorty/keys/server.key ${WSS_LPORT} ${DESTINATION_SSH_ADDR}:${DESTINATION_SSH_PORT}