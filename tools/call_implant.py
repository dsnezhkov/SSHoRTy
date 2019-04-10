#!/usr/bin/env python
from ctypes import *

implant = 'out/4fa48c653682c3b04add14f434a3114/chrome'
dll = cdll.LoadLibrary(implant)
res = dll.entry()
print(res)

