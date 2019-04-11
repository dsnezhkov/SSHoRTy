#!/usr/bin/env python3
import sys
import os
import subprocess
from ctypes import *


def irun(path_implant, itype):
    print("In Mrun")

    if itype == "bin":
        print("Bin")
        process = subprocess.Popen(
            path_implant,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)

        process.wait()

    if itype == "lib":
        print("Lib")
        dll = cdll.LoadLibrary(path_implant)
        res = dll.entry()


def daemonize(idir):

    try:
        pid = os.fork()
        if pid > 0:
            # exit first parent
            sys.exit(0)
    except OSError as err:
        sys.stderr.write('fork #1 failed: {0}\n'.format(err))
        sys.exit(1)

    # decouple from parent environment
    os.chdir(idir)
    os.setsid()
    os.umask(0)

    # do second fork
    try:
        pid = os.fork()
        if pid > 0:

            # exit from second parent
            sys.exit(0)
    except OSError as err:
        sys.stderr.write('fork #2 failed: {0}\n'.format(err))
        sys.exit(1)

    # redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    si = open(os.devnull, 'r')
    so = open(os.devnull, 'a+')
    se = open(os.devnull, 'a+')

    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())


if __name__ == '__main__':
    # Start the daemon
    if len(sys.argv) < 3:
        print("Usage: <type> /full/path/to/payload")
        print("       type: bin|lib ")
        sys.exit(1)

    # preserve before daemonizing
    itype = str(sys.argv[1])
    ipath = str(os.path.abspath(sys.argv[2]))
    daemonize("/tmp")
    irun(ipath, itype)


