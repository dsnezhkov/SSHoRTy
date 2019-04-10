#!/usr/bin/env bash
./tools/build_implant.sh  ./conf/build.profile
./tools/transfer_implant_keys.sh  ./out/4fa48c653682c3b04add14f434a3114/4fa48c653682c3b04add14f434a3114.tar.gz
./tools/call_implant.py
