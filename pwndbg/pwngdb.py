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

import re
import struct
import subprocess

import gdb

import pwndbg.gdblib.arch
import pwndbg.gdblib.proc
import pwndbg.search
import pwndbg.gdblib.symbol
import pwndbg.gdblib.memory
import pwndbg.gdblib.vmmap

magic_variable = ["__malloc_hook", "__free_hook", "__realloc_hook", "stdin", "stdout", "_IO_list_all",
                  "__after_morecore_hook"]
magic_function = ["system", "execve", "open", "read", "write", "gets", "setcontext+0x35"]


def to_int(val):
    try:
        return int(str(val), 0)
    except:
        return val


def procmap():
    data = gdb.execute("info proc exe", to_string=True)
    pid = re.search("process.*", data)
    if pid:
        pid = pid.group().split()[1]
        with open("/proc/{}/maps".format(pid), "r") as maps:
            return maps.read()
    else:
        return "error"


def libcbase():
    for p in pwndbg.vmmap.get():
        if re.search(r".*libc-.*", p.objfile):
            libcaddr = p.start
            gdb.execute("set $libc={}".format(hex(libcaddr)))
            return libcaddr
    return 0


def getheapbase():
    for p in pwndbg.vmmap.get():
        if re.search(r".*heap\]", p.objfile):
            heapbase = p.start
            gdb.execute("set $heap={}".format(hex(heapbase)))
            return heapbase
    return 0


def ldbase():
    for p in pwndbg.vmmap.get():
        if re.search(r".*ld.*\.so", p.objfile):
            ldbase = p.start
            gdb.execute("set $ld={}".format(hex(ldbase)))
            return ldbase
    return 0


def codeaddr():  # ret (start, end)
    pat = ".*" + pwndbg.proc.exe
    if pwndbg.vmmap.get() and re.search(pat, pwndbg.vmmap.get()[0].objfile):
        codebaseaddr = pwndbg.vmmap.get()[0].start
        codeend = pwndbg.vmmap.get()[0].end
        gdb.execute("set $code=%s" % hex(codebaseaddr))
        return (codebaseaddr, codeend)
    else:
        return (0, 0)


def gettls():
    arch = pwndbg.arch.current

    if arch == "i386":
        vsysaddr = gdb.execute("info functions __kernel_vsyscall", to_string=True).split("\n")[-2].split()[0].strip()
        value = struct.pack("<L", int(vsysaddr, 16))
        sysinfo = [address for address in pwndbg.search.search(value)][0]
        return sysinfo - 0x10
    elif arch == "x86-64":
        gdb.execute("call (int)arch_prctl(0x1003, $rsp-8)", to_string=True)
        data = gdb.execute("x/xg $rsp-8", to_string=True)
        return int(data.split(":")[1].strip(), 16)
    else:
        return -1


# pwndbg already has canary command
# def getcanary():
#     arch = pwndbg.arch.current
#     tlsaddr = gettls()
#     if arch == "i386" :
#         offset = 0x14
#         result = gdb.execute("x/xw " + hex(tlsaddr + offset), to_string=True).split(":")[1].strip()
#         return int(result, 16)
#     elif arch == "x86-64" :
#         offset = 0x28
#         result = gdb.execute("x/xg " + hex(tlsaddr + offset), to_string=True).split(":")[1].strip()
#         return int(result, 16)
#     else :
#         return -1

def getoff(symbol):
    libc = libcbase()
    symbol = to_int(symbol)

    if isinstance(symbol, int):
        return symbol - libc
    else:
        try:
            data = gdb.execute("x/x " + symbol, to_string=True)
            if "No symbol" in data:
                return -1
            else:
                symaddr = int(re.search("0x.*[0-9a-f] ", data).group()[:-1], 16)
                return symaddr - libc
        except:
            return -1


def iscplus():
    return "CXX" in subprocess.check_output("readelf -s {}".format(pwndbg.proc.exe), shell=True).decode("utf8")


def searchcall(symbol):
    procname = pwndbg.proc.exe
    cmd = "objdump -d -M intel {} {}".format("--demangle" if iscplus() else "", procname)
    cmd += "| grep 'call.*{}@plt'".format(symbol)
    try:
        return subprocess.check_output(cmd, shell=True).decode("utf8").strip("\n")
    except:
        return -1


def ispie():
    result = subprocess.check_output("readelf -h {}".format(pwndbg.proc.exe), shell=True).decode("utf8")
    return True if re.search("DYN", result) else False


def showfp(addr):
    if addr:
        cmd = "p *(struct _IO_FILE_plus *)" + hex(addr)
        try:
            result = gdb.execute(cmd)
        except:
            print("Can't not access 0x%x" % addr)
    else:
        print("You need to specify an address")


def showfpchain():
    _IO_list_all_addr = pwndbg.symbol.address("_IO_list_all")
    head = pwndbg.memory.read(_IO_list_all_addr, pwndbg.arch.ptrsize)
    head = int.from_bytes(head, byteorder=pwndbg.arch.endian)
    print("\033[32mfpchain:\033[1;37m ", end="")
    chain = head
    print("0x%x" % chain, end="")
    try:
        while chain != 0:
            print(" --> ", end="")
            chain_addr = int(gdb.parse_and_eval("&((struct _IO_FILE_plus *)" + hex(chain) + ").file._chain"))
            chain = pwndbg.memory.read(chain_addr, pwndbg.arch.ptrsize)
            chain = int.from_bytes(chain, byteorder=pwndbg.arch.endian)
            print("0x%x" % chain, end="")
        print()
    except:
        print("Chain is corrupted")


def testorange(addr):
    result = True
    mode_addr = int(gdb.parse_and_eval("&((struct _IO_FILE_plus *)" + hex(addr) + ").file._mode"))
    mode = pwndbg.memory.read(mode_addr, pwndbg.arch.ptrsize)
    mode = int.from_bytes(mode, byteorder=pwndbg.arch.endian) & 0xffffffff
    write_ptr_address = int(gdb.parse_and_eval("&((struct _IO_FILE_plus *)" + hex(addr) + ").file._IO_write_ptr"))
    write_ptr = pwndbg.memory.read(write_ptr_address, pwndbg.arch.ptrsize)
    write_ptr = int.from_bytes(write_ptr, byteorder=pwndbg.arch.endian)
    write_base_addr = int(gdb.parse_and_eval("&((struct _IO_FILE_plus *)" + hex(addr) + ").file._IO_write_base"))
    write_base = pwndbg.memory.read(write_base_addr, pwndbg.arch.ptrsize)
    write_base = int.from_bytes(write_base, byteorder=pwndbg.arch.endian)
    if mode < 0x80000000 and mode != 0:
        try:
            wide_data_addr = int(gdb.parse_and_eval("&((struct _IO_FILE_plus *)" + hex(addr) + ").file._wide_data"))
            wide_data = pwndbg.memory.read(wide_data_addr, pwndbg.arch.ptrsize)
            wide_data = int.from_bytes(wide_data, byteorder=pwndbg.arch.endian)
            w_write_ptr_addr = int(
                gdb.parse_and_eval("&((struct _IO_wide_data *)" + hex(wide_data) + ")._IO_write_ptr"))
            w_write_ptr = pwndbg.memory.read(w_write_ptr_addr, pwndbg.arch.ptrsize)
            w_write_ptr = int.from_bytes(w_write_ptr, byteorder=pwndbg.arch.endian)
            w_write_base_addr = int(
                gdb.parse_and_eval("&((struct _IO_wide_data *)" + hex(wide_data) + ")._IO_write_base"))
            w_write_base = pwndbg.memory.read(w_write_base_addr, pwndbg.arch.ptrsize)
            w_write_base = int.from_bytes(w_write_base, byteorder=pwndbg.arch.endian)
            if w_write_ptr <= w_write_base:
                print("\033[;1;31m_wide_data->_IO_write_ptr(0x%x) < _wide_data->_IO_write_base(0x%x)\033[1;37m" % (
                w_write_ptr, w_write_base))
                result = False
        except:
            print("\033;1;31mCan't access wide_data\033[1;37m")
            result = False
    else:
        if write_ptr <= write_base:
            print("\033[;1;31m_IO_write_ptr(0x%x) < _IO_write_base(0x%x)\033[1;37m" % (write_ptr, write_base))
            result = False
    if result:
        print("Result : \033[34mTrue\033[37m")
        overflow_addr = int(gdb.parse_and_eval("&((struct _IO_FILE_plus *)" + hex(addr) + ").vtable.__overflow"))
        overflow = pwndbg.memory.read(overflow_addr, pwndbg.arch.ptrsize)
        overflow = int.from_bytes(overflow, byteorder=pwndbg.arch.endian)
        print("Func : \033[33m 0x%x\033[1;37m" % overflow)
    else:
        print("Result : \033[31mFalse\033[1;37m")
