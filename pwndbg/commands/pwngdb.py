#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Pwngdb by angelboy

https://github.com/scwuaptx/Pwngdb
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import subprocess
import argparse

import gdb

import pwndbg.commands
import pwndbg.gdblib.arch
import pwndbg.gdblib.proc
import pwndbg.search
import pwndbg.gdblib.regs
import pwndbg.gdblib.symbol
import pwndbg.gdblib.memory
import pwndbg.pwngdb as pwngdb



parser = argparse.ArgumentParser()
parser.description = "Automatically attach process by filename."
parser.add_argument("processname", nargs='?', type=str, default=None, help="Process name")
@pwndbg.commands.ArgparsedCommand(parser)
def at(processname=None):
    if processname is None:
        processname = pwndbg.gdblib.proc.exe
    try :
        pidlist = map(int, subprocess.check_output('pidof $(basename {})'.format(processname), shell=True).decode('utf8').split())

        for pid in pidlist:
            if pid == pwndbg.gdblib.proc.pid:
                continue
            print('attaching to {} ...'.format(processname))
            gdb.execute("attach {}".format(pid))
            pwngdb.getheapbase()
            pwngdb.libcbase()
            pwngdb.codeaddr()
            pwngdb.ldbase()
            return

        print("already attached on {}".format(pwndbg.gdblib.proc.pid))
    except:
        print("no such process:", processname)


@pwndbg.commands.ArgparsedCommand("Get libc base.")
@pwndbg.commands.OnlyWhenRunning
def libc():
    print("\033[34m" + "libc : " + "\033[37m" + hex(pwngdb.libcbase()))


@pwndbg.commands.ArgparsedCommand("Get heapbase.")
@pwndbg.commands.OnlyWhenRunning
def heapbase():
    heapbase_addr = pwngdb.getheapbase()
    if heapbase_addr :
        print("\033[34m" + "heapbase : " + "\033[37m" + hex(heapbase_addr))
    else :
        print("heap not found")


@pwndbg.commands.ArgparsedCommand("Get ld.so base.")
@pwndbg.commands.OnlyWhenRunning
def ld():
    print("\033[34m" + "ld : " + "\033[37m" + hex(pwngdb.ldbase()))


@pwndbg.commands.ArgparsedCommand("Get text base.")
@pwndbg.commands.OnlyWhenRunning
def codebase():
    codebs = pwngdb.codeaddr()[0]
    print("\033[34m" + "codebase : " + "\033[37m" + hex(codebs))


@pwndbg.commands.ArgparsedCommand("Get tls base.")
@pwndbg.commands.OnlyWhenRunning
def pwngdb_tls():
    tlsaddr = pwngdb.gettls()
    if tlsaddr != -1:
        print("\033[34m" + "tls : " + "\033[37m" + hex(tlsaddr))
    else:
        print("cannot get tls")


parser = argparse.ArgumentParser()
parser.description = "Calculate the index of format string."
parser.add_argument("addr", nargs='?', type=int, help="Address of the target")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def fmtarg(addr):
    if pwndbg.gdblib.arch.current == "i386":
        reg = "esp"
    elif pwndbg.gdblib.arch.current == "x86-64":
        reg = "rsp"
    else:
        print("arch not support")
        return
    start = pwndbg.gdblib.regs[reg]
    idx = (addr - start) / (pwndbg.gdblib.arch.ptrsize) + 6
    print("The index of format argument : %d" % idx)


parser = argparse.ArgumentParser()
parser.description = "Calculate the offset of libc."
parser.add_argument("symbol", nargs='?', type=str, help="A symbol or an address")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def off(symbol):
    symaddr = pwngdb.getoff(symbol)
    if symaddr == -1 :
        print("symbol not found")
        return

    if type(symbol) is int :
        print("\033[34m" + hex(symbol)  + " : " + "\033[37m" + hex(symaddr))
    else :
        print("\033[34m" + symbol  + " : " + "\033[37m" + hex(symaddr))


parser = argparse.ArgumentParser()
parser.description = "Find the syscall gadget."
parser.add_argument("mapping_name", nargs='?', type=str, default=None, help="Mapping to search [e.g. libc]")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def findsyscall(mapping_name=None):
    if mapping_name is None:
        mapping_name = pwndbg.gdblib.proc.exe
    arch = pwndbg.gdblib.arch.current

    if arch == "x86-64" :
        gdb.execute("search -e -x 0f05 {}".format(mapping_name))
    elif arch == "i386":
        gdb.execute("search -e -x cd80 {}".format(mapping_name))
    elif arch == "arm":
        gdb.execute("search -e -x 00df80bc {}".format(mapping_name))
    elif arch == "aarch64":
        gdb.execute("search -e -x 010000d4 {}".format(mapping_name))
    else :
        print("arch not support")


parser = argparse.ArgumentParser()
parser.description = "Find some function call."
parser.add_argument("symbol", nargs='?', type=str, help="A symbol of a function")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWithFile
def findcall(symbol):
    call = pwngdb.searchcall(symbol)
    print(call) if call != -1 else print("symbol not found")


@pwndbg.commands.ArgparsedCommand("Print the GOT table by objdump.")
@pwndbg.commands.OnlyWithFile
def objdump_got():
    cmd = "objdump -R {} {}".format("--demangle" if pwngdb.iscplus() else "", pwndbg.gdblib.proc.exe)
    print(subprocess.check_output(cmd, shell=True)[:-2].decode("utf8").strip())

@pwndbg.commands.ArgparsedCommand("Print dynamic section.")
@pwndbg.commands.OnlyWithFile
def dyn():
    print(subprocess.check_output("readelf -d {}".format(pwndbg.gdblib.proc.exe), shell=True).decode("utf8").strip())


@pwndbg.commands.ArgparsedCommand("Print usefual variables or function in glibc.")
@pwndbg.commands.OnlyWhenRunning
def magic():
    print("========== function ==========")
    for f in pwngdb.magic_function :
        print("\033[34m" + f  + ":" + "\033[33m" +hex(pwngdb.getoff(f))) 
    print("\033[00m========== variables ==========")
    for v in pwngdb.magic_variable:
        addr = pwndbg.symbol.address(v)
        if addr is None:
            print("\033[34m" + v + ":" + "\033[33m" + "not found")
        offset = addr - pwngdb.libcbase()
        pad = 36 - len(v) - len(hex(offset)) - 2
        print("\033[34m%s\033[33m(%s)\033[37m%s: \033[37m0x%016x" % (v, hex(offset), ' ' *pad, addr))


parser = argparse.ArgumentParser()
parser.description = "Show FILE structure."
parser.add_argument("addr", nargs='?', type=int, help="Address of the target")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def fp(addr):
    pwngdb.showfp(addr)


@pwndbg.commands.ArgparsedCommand("Show FILE chain.")
@pwndbg.commands.OnlyWithFile
def fpchain():
    pwngdb.showfpchain()


parser = argparse.ArgumentParser()
parser.description = "Test house of orange."
parser.add_argument("addr", nargs='?', type=int, help="Address of the target")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def orange(addr):
    pwngdb.testorange(addr)

parser = argparse.ArgumentParser()
parser.description = "Set the breakpoint at some function call."
parser.add_argument("symbol", nargs='?', type=str, help="A symbol of a function")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWithFile
def bcall(symbol):
    call = pwngdb.searchcall(symbol)
    if call == -1:
        print("symbol not found")
        return
    codebase = pwngdb.codeaddr()[0] if pwngdb.ispie() else 0
    for callbase in call.split('\n'):
        addr = int(callbase.split(':')[0], 16) + codebase
        gdb.execute("b *{}".format(hex(addr)))

