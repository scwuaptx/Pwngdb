#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Pwngdb by angenboy

https://github.com/scwuaptx/Pwngdb
"""

import argparse

import pwndbg.commands
import pwndbg.angelheap as angelheap

# initialize angelheap when process starts
pwndbg.commands.Command(angelheap.init_angelheap, command_name='hook-run')

parser = argparse.ArgumentParser()
parser.description = "Trace the malloc and free and detect some error."
parser.add_argument("option", nargs='?', type=str, default="on", help="on or off")
@pwndbg.commands.ArgparsedCommand(parser)
def tracemalloc(option="on"):
    if option == "on":
        try:
            angelheap.trace_malloc()
        except:
            print("Can't create Breakpoint")
    else:
        angelheap.dis_trace_malloc()


parser = argparse.ArgumentParser()
parser.description = "Print some information of heap."
parser.add_argument("arena", nargs='?', type=int, default=None, help="Address of arena")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def heapinfo(arena=None):
    angelheap.putheapinfo(arena)


@pwndbg.commands.ArgparsedCommand("Print some information of multiheap.")
@pwndbg.commands.OnlyWhenRunning
def heapinfoall():
    angelheap.putheapinfoall()


@pwndbg.commands.ArgparsedCommand("Print all arena info.")
@pwndbg.commands.OnlyWhenRunning
def arenainfo():
    angelheap.putarenainfo()


parser = argparse.ArgumentParser()
parser.description = "Print chunk information of victim."
parser.add_argument("victim", nargs='?', type=int, help="Address of victim.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def chunkinfo(victim):
    angelheap.chunkinfo(victim)


parser = argparse.ArgumentParser()
parser.description = "Print chunk is freeable."
parser.add_argument("ptr", nargs='?', type=int, help="Address of user ptr.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def free(ptr):
    angelheap.freeptr(ptr)


parser = argparse.ArgumentParser()
parser.description = "Print chunk information of user ptr."
parser.add_argument("ptr", nargs='?', type=int, help="Address of user ptr.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def chunkptr(ptr):
    angelheap.chunkptr(ptr)


parser = argparse.ArgumentParser()
parser.description = "Print merge information of victim."
parser.add_argument("victim", nargs='?', type=int, help="Address of victim.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def mergeinfo(victim):
    angelheap.mergeinfo(victim)


parser = argparse.ArgumentParser()
parser.description = "Calculate the nb in the house of force."
parser.add_argument("target", nargs='?', type=int, help="Address of target you want to calculate.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def force(target):
    angelheap.force(target)


@pwndbg.commands.ArgparsedCommand("Print the fastbin.")
@pwndbg.commands.OnlyWhenRunning
def printfastbin():
    angelheap.putfastbin()


@pwndbg.commands.ArgparsedCommand("Print the inuse chunk.")
@pwndbg.commands.OnlyWhenRunning
def inused():
    angelheap.putinused()


@pwndbg.commands.ArgparsedCommand("Parse heap.")
@pwndbg.commands.OnlyWhenRunning
def parseheap():
    angelheap.parse_heap()


parser = argparse.ArgumentParser()
parser.description = "Get fake fast chunks information."
parser.add_argument("addr", nargs='?', type=int, help="Address of the fake chunk.")
parser.add_argument("size", nargs='?', type=int, help="Size of the fake chunk.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def fakefast(addr, size):
    angelheap.get_fake_fast(addr, size)
