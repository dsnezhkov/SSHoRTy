#!/bin/bash
openssl req -x509 -nodes -newkey rsa:2048 -keyout sslkey.pem -out sslcert.pem -days 365 -subj "/C=GB/ST=London/L=London/O=Global Security/OU=IT Department/CN=example.com"
