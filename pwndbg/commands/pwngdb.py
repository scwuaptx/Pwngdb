#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Pwngdb by angenboy

https://github.com/scwuaptx/Pwngdb
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import copy
import os
import re
import subprocess

import gdb

import pwndbg.commands
import pwndbg.arch
import pwndbg.proc
import pwndbg.search
from pwndbg.pwngdb import *

@pwndbg.commands.Command
def at(*arg):
    """Automatically attach process by filename."""
    processname = arg[0] if len(arg) > 0 else pwndbg.proc.exe

    try :
        pidlist = map(int, subprocess.check_output('pidof $(basename {})'.format(processname), shell=True).decode('utf8').split())

        for pid in pidlist:
            if pid == pwndbg.proc.pid:
                continue
            print('attaching to {} ...'.format(processname))
            gdb.execute("attach {}".format(pid))
            getheapbase()
            libcbase()
            codeaddr()
            ldbase()
            return

        print("already attached on {}".format(pwndbg.proc.pid))
    except:
        print("no such process")

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def libc():
    """ Get libc base """
    print("\033[34m" + "libc : " + "\033[37m" + hex(libcbase()))

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def heap():
    """ Get heapbase """
    heapbase = getheapbase()
    if heapbase :
        print("\033[34m" + "heapbase : " + "\033[37m" + hex(heapbase))
    else :
        print("heap not found")

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def ld():
    """ Get ld.so base """
    print("\033[34m" + "ld : " + "\033[37m" + hex(ldbase()))

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def codebase():
    """ Get text base """
    codebs = codeaddr()[0]
    print("\033[34m" + "codebase : " + "\033[37m" + hex(codebs))

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def tls():
    """ Get tls base """
    tlsaddr = gettls()
    if tlsaddr != -1:
        print("\033[34m" + "tls : " + "\033[37m" + hex(tlsaddr))
    else:
        print("cannot get tls")

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def canary():
    """ Get canary value """
    canary = getcanary()
    if canary != -1:
        print("\033[34m" + "canary : " + "\033[37m" + hex(canary))
    else:
        print("cannot get cannary")

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def fmtarg(addr):
    """ Calculate the index of format string """
    if pwndbg.arch.current == "i386":
        reg = "esp"
    elif pwndbg.arch.current == "x86-64":
        reg = "rsp"
    else:
        print("arch not support")
        return

    start = int(gdb.execute("info register {}".format(reg), to_string=True).split()[1].strip(), 16)
    idx = (int(addr, 0) - start) / (pwndbg.arch.ptrsize) + 6
    print("The index of format argument : %d" % idx)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def off(symbol):
    """ Calculate the offset of libc """
    symaddr = getoff(symbol)
    if symaddr == -1 :
        print("symbol not found")
        return

    if type(symbol) is int :
        print("\033[34m" + hex(symbol)  + " : " + "\033[37m" + hex(symaddr))
    else :
        print("\033[34m" + symbol  + " : " + "\033[37m" + hex(symaddr))

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def findsyscall(*arg):
    """ ind the syscall gadget"""
    vmmap = arg[0] if len(arg) > 0 else pwndbg.proc.exe
    arch = pwndbg.arch.current
    start, end = codeaddr()

    if arch == "x86-64" :
        gdb.execute("search -e -x 0f05 {}".format(vmmap))
    elif arch == "i386":
        gdb.execute("search -e -x cd80 {}".format(vmmap))
    elif arch == "arm":
        gdb.execute("search -e -x 00df80bc {}".format(vmmap))
    elif arch == "aarch64":
        gdb.execute("search -e -x 010000d4 {}".format(vmmap))
    else :
        print("arch not support")

@pwndbg.commands.Command
@pwndbg.commands.OnlyWithFile
def got():
    """ Print the got table """
    cmd = "objdump -R {} {}".format("--demangle" if iscplus() else "", pwndbg.proc.exe)
    print(subprocess.check_output(cmd, shell=True)[:-2].decode("utf8").strip())

@pwndbg.commands.Command
@pwndbg.commands.OnlyWithFile
def dyn():
    """ Print dynamic section """
    print(subprocess.check_output("readelf -d {}".format(pwndbg.proc.exe), shell=True).decode("utf8").strip())

@pwndbg.commands.Command
@pwndbg.commands.OnlyWithFile
def findcall(symbol):
    """ Find some function call """
    call = searchcall(symbol)
    print(call) if call != -1 else print("symbol not found")

@pwndbg.commands.Command
@pwndbg.commands.OnlyWithFile
def bcall(symbol):
    """ Set the breakpoint at some function call """
    call = searchcall(symbol)
    if call == -1:
        print("symbol not found")
        return

    codebase = codeaddr()[0] if ispie() else 0
    for callbase in call.split('\n'):
        addr = int(callbase.split(':')[0], 16) + codebase
        gdb.execute("b *{}".format(hex(addr)))
