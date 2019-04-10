#!/bin/bash

usage(){
   echo "$1"
   echo "$0 /path/<implant>.tar.gz"
   exit 1
}

if [[ $# -eq 0 ]]
then
    usage "need file"
fi

if [[  -f  $1 ]]
then
    source $1
else
    usage $0 "Cannot find implant data file"
fi


IMPLANTFILE=$1
_t=$(/usr/bin/basename -- "$1")
IMPLANTID="${_t%.*.*}"
IHOST=167.99.88.24
IUSER=root
IDIR="/tmp"
INSTALL_SCRIPT="./tools/install_implant.sh"

echo "Copying ${IMPLANT_FILE} and ${INSTALL_SCRIPT} to ${IHOST}"
scp $IMPLANTFILE ${INSTALL_SCRIPT} ${IUSER}@${IHOST}:${IDIR}

echo "Deleting remote user: ${IMPLANTID}"
ssh -tt ${IUSER}@${IHOST} userdel -r ${IMPLANTID}

echo "Installing: ${IMPLANTID}"
ssh -tt ${IUSER}@${IHOST} ${IDIR}/install_implant.sh ${IDIR}/${IMPLANTID}.tar.gz

