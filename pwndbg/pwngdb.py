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

import re
import struct
import subprocess

import gdb

import pwndbg.arch
import pwndbg.proc
import pwndbg.search

def to_int(val):
    try:
        return int(str(val), 0)
    except:
        return val

def procmap():
    data = gdb.execute("info proc exe", to_string=True)
    pid = re.search("process.*", data)
    if pid :
        pid = pid.group().split()[1]
        with open("/proc/{}/maps".format(pid), "r") as maps:
            return maps.read()
    else :
        return "error"

def libcbase():
    data = re.search(".*libc.*\.so", procmap())
    if data :
        libcaddr = data.group().split("-")[0]
        gdb.execute("set $libc={}".format(hex(int(libcaddr, 16))))
        return int(libcaddr, 16)
    else :
        return 0

def getheapbase():
    data = re.search(".*heap\]", procmap())
    if data :
        heapbase = data.group().split("-")[0]
        gdb.execute("set $heap={}".format(hex(int(heapbase, 16))))
        return int(heapbase, 16)
    else :
        return 0

def ldbase():
    data = re.search(".*ld.*\.so", procmap())
    if data :
        ldaddr = data.group().split("-")[0]
        gdb.execute("set $ld={}".format(hex(int(ldaddr, 16))))
        return int(ldaddr, 16)
    else :
        return 0

def codeaddr(): # ret (start, end)
    pat = ".*" + pwndbg.proc.exe
    data = re.findall(pat, procmap())
    if data :
        codebaseaddr = data[0].split("-")[0]
        codeend = data[0].split("-")[1].split()[0]
        gdb.execute("set $code={}".format(hex(int(codebaseaddr, 16))))
        return (int(codebaseaddr, 16), int(codeend, 16))
    else :
        return (0, 0)

def gettls():
    arch = pwndbg.arch.current

    if arch == "i386" :
        vsysaddr = gdb.execute("info functions __kernel_vsyscall", to_string=True).split("\n")[-2].split()[0].strip()
        value = struct.pack("<L", int(vsysaddr, 16))
        sysinfo = [address for address in pwndbg.search.search(value)][0]
        return sysinfo - 0x10
    elif arch == "x86-64" :
        gdb.execute("call arch_prctl(0x1003, $rsp-8)", to_string=True)
        data = gdb.execute("x/xg $rsp-8", to_string=True)
        return int(data.split(":")[1].strip(), 16)
    else:
        return -1

def getcanary():
    arch = pwndbg.arch.current
    tlsaddr = gettls()
    if arch == "i386" :
        offset = 0x14
        result = gdb.execute("x/xw " + hex(tlsaddr + offset), to_string=True).split(":")[1].strip()
        return int(result, 16)
    elif arch == "x86-64" :
        offset = 0x28
        result = gdb.execute("x/xg " + hex(tlsaddr + offset), to_string=True).split(":")[1].strip()
        return int(result, 16)
    else :
        return -1

def getoff(symbol):
    libc = libcbase()
    symbol = to_int(symbol)

    if isinstance(symbol, int):
        return symbol - libc
    else :
        try :
            data = gdb.execute("x/x " + symbol, to_string=True)
            if "No symbol" in data:
                return -1
            else :
                symaddr = int(re.search("0x.*[0-9a-f] ", data).group()[:-1], 16)
                return symaddr - libc
        except :
            return -1

def iscplus():
    return "CXX" in subprocess.check_output("readelf -s {}".format(pwndbg.proc.exe), shell=True).decode("utf8")

def searchcall(symbol):
    procname = pwndbg.proc.exe
    cmd = "objdump -d -M intel {} {}".format("--demangle" if iscplus() else "", procname)
    cmd += "| grep 'call.*{}@plt'".format(symbol)
    try :
        return subprocess.check_output(cmd, shell=True).decode("utf8").strip("\n")
    except :
        return -1

def ispie():
    result = subprocess.check_output("readelf -h {}".format(pwndbg.proc.exe), shell=True).decode("utf8")
    return True if re.search("DYN", result) else False
