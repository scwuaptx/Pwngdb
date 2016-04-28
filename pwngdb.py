import gdb
import subprocess
import re
import copy
main_arena = 0
main_arena_off = 0 #You need to modify it if libc is stripd
main_arena_off_32 = 0x1b7840  #You need to modify it 
#main_arena_off_32 = 0
top = {}
_int_malloc_off = 0x818d0 # You need to modify it
_int_malloc_off_32 = 0  # You need to modfiy it
_int_free_off = 0x80690 # You need to modify it
_int_free_off_32 = 0 # You need to modify it
malloc_off = 0 # You need to modify it
free_off = 0 # You need to modify it
malloc_off_32 = 0x73260 # You need to modify it
free_off_32 = 0x73880 # You need to modify it
last_remainder = {}
fastbinsize = 10
fastbin = []
freememoryarea = {} #using in parse
allocmemoryarea = {}
freerecord = {} # using in trace
unsortbin = []
smallbin = {}  #{size:bin}
largebin = {}
tracemode = False
tracelargebin = True
mallocbp = None
freebp = None
print_overlap = True
DEBUG = False  #debug msg (free and malloc) if you want


class Malloc_bp_ret(gdb.FinishBreakpoint):
    global allocmemoryarea
    global freerecord
    def __init__(self,arg):
        gdb.FinishBreakpoint.__init__(self,gdb.newest_frame(),internal=True)
        self.silent = True
        self.arg = arg
    
    def stop(self):
        chunk = {}
        arch = getarch()
        if arch == "x86-64" :
            ptrsize = 8
            word = "x/gx "
            value = int(self.return_value)
            chunk["addr"] = value - ptrsize*2
        else :
            ptrsize = 4
            word = "x/wx "
            cmd = "info register $eax"
            value = int(gdb.execute(cmd,to_string=True).split()[1].strip(),16)
            chunk["addr"] = value - ptrsize*2
        if value == 0 :
            return False

        cmd = word + hex(chunk["addr"] + ptrsize)
        chunk["size"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) & 0xfffffffffffffff8
        overlap,status = check_overlap(chunk["addr"],chunk["size"],allocmemoryarea)
        if overlap and status == "error" :
            if DEBUG :
                print("\033[34m>--------------------------------------------------------------------------------------<\033[37m")
                msg = "\033[33mmalloc(0x%x)\033[37m" % self.arg
                print("%-40s = 0x%x \033[31m overlap detected !! (0x%x)\033[37m" % (msg,chunk["addr"]+ptrsize*2,overlap["addr"]))
                print("\033[34m>--------------------------------------------------------------------------------------<\033[37m")
            else :
                print("\033[31moverlap detected !! (0x%x)\033[37m" % overlap["addr"])
            del allocmemoryarea[hex(overlap["addr"])]
        else :
            if DEBUG:
                msg = "\033[33mmalloc(0x%x)\033[37m" % self.arg
                print("%-40s = 0x%x" % (msg,chunk["addr"] + ptrsize*2))
        allocmemoryarea[hex(chunk["addr"])] = copy.deepcopy((chunk["addr"],chunk["addr"]+chunk["size"],chunk))
        if hex(chunk["addr"]) in freerecord :
            freechunktuple = freerecord[hex(chunk["addr"])]
            freechunk = freechunktuple[2]
            splitchunk = {}
            del freerecord[hex(chunk["addr"])]
            if chunk["size"] != freechunk["size"] :
                splitchunk["addr"] = chunk["addr"] + chunk["size"]
                splitchunk["size"] = freechunk["size"] - chunk["size"]
                freerecord[hex(splitchunk["addr"])] = copy.deepcopy((splitchunk["addr"],splitchunk["addr"]+splitchunk["size"],splitchunk))
        if self.arg >= 128*ptrsize :
            Malloc_consolidate()

class Malloc_Bp_handler(gdb.Breakpoint):
    def stop(self):
        arch = getarch()
        ptrsize = 4
        if arch == "x86-64":
            ptrsize = 8
            if _int_malloc_off != 0 :
                reg = "$rsi"
            else :
                reg = "$rdi"
            word = "x/gx "
            arg = int(gdb.execute("info register " + reg,to_string=True).split()[1].strip(),16)
        else :
            ptrsize = 4
            word = "x/wx "
            if _int_malloc_off_32 != 0 :
                arg = int(gdb.execute("x/wx $esp+8" ,to_string=True).split(":")[1].strip(),16)
            else :
                arg = int(gdb.execute("x/wx $esp+4" ,to_string=True).split(":")[1].strip(),16)
        Malloc_bp_ret(arg)
        return False

class Free_Bp_handler(gdb.Breakpoint):
    def stop(self):
        global allocmemoryarea
        global freerecord
#        get_heap_info()
        get_top_lastremainder()
        arch = getarch()
        ptrsize = 4
        if arch == "x86-64":
            ptrsize = 8
            word = "x/gx "
            if _int_free_off != 0 :
                reg = "$rsi"
                result = int(gdb.execute("info register " + reg,to_string=True).split()[1].strip(),16) + 0x10
            else :
                reg = "$rdi"
                result = int(gdb.execute("info register " + reg,to_string=True).split()[1].strip(),16)
        else :
            ptrsize = 4
            word = "x/wx "
            if _int_free_off_32 != 0:
                result = int(gdb.execute("x/wx $esp+8" ,to_string=True).split(":")[1].strip(),16) + 0x8
            else :
                result = int(gdb.execute("x/wx $esp+4" ,to_string=True).split(":")[1].strip(),16)
        chunk = {}
        prevfreed = False
        chunk["addr"] = result - ptrsize*2
        cmd = word + hex(chunk["addr"] + ptrsize)
        size = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
        chunk["size"] = size & 0xfffffffffffffff8
        if (size & 1) == 0 :
            prevfreed = True
#        overlap,status = check_overlap(chunk["addr"],chunk["size"],freememoryarea)
        overlap,status = check_overlap(chunk["addr"],chunk["size"],freerecord)
        if overlap and status == "error" :
            if DEBUG :
                msg = "\033[32mfree(0x%x)\033[37m (size = 0x%x)" % (result,chunk["size"])
                print("\033[34m>--------------------------------------------------------------------------------------<\033[37m")
                print("%-25s \033[31m double free detected !! (0x%x(size:0x%x))\033[37m" % (msg,overlap["addr"],overlap["size"]))
                print("\033[34m>--------------------------------------------------------------------------------------<\033[37m",end="")
            else :
                print("\033[31mdouble free detected !! (0x%x)\033[37m" % overlap["addr"])
            del freerecord[hex(overlap["addr"])]
        else :
            if DEBUG :
                msg = "\033[32mfree(0x%x)\033[37m" % result
                print("%-40s (size = 0x%x)" % (msg,chunk["size"]),end="")

        if chunk["size"] <= 0x80 :
            freerecord[hex(chunk["addr"])] = copy.deepcopy((chunk["addr"],chunk["addr"]+chunk["size"],chunk))
            if DEBUG :
                print("")
            if hex(chunk["addr"]) in allocmemoryarea :
                del allocmemoryarea[hex(chunk["addr"])]
            return False

        prevchunk = {}
        if prevfreed :
            cmd = word + hex(chunk["addr"])
            prevchunk["size"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) & 0xfffffffffffffff8
            prevchunk["addr"] = chunk["addr"] - prevchunk["size"]
            if hex(prevchunk["addr"]) not in freerecord :
                print("\033[31m confuse in prevchunk 0x%x" % prevchunk["addr"])
            else :
                prevchunk["size"] += chunk["size"]
                del freerecord[hex(prevchunk["addr"])]

        nextchunk = {}
        nextchunk["addr"] = chunk["addr"] + chunk["size"]
        
        if nextchunk["addr"] == top["addr"] :
            if hex(chunk["addr"]) in allocmemoryarea :
                del allocmemoryarea[hex(chunk["addr"])]
            if DEBUG :
                print("")
            return False

        cmd = word + hex(nextchunk["addr"] + ptrsize)
        nextchunk["size"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) & 0xfffffffffffffff8
        cmd = word + hex(nextchunk["addr"] + nextchunk["size"] + ptrsize)
        nextinused = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) & 1
        
        if nextinused == 0 and prevfreed: #next chunk is freed                       
            if hex(nextchunk["addr"]) not in freerecord :
                print("\033[31m confuse in nextchunk 0x%x" % nextchunk["addr"])
            else :
                prevchunk["size"] += nextchunk["size"]
                del freerecord[hex(nextchunk["addr"])]
                chunk = prevchunk
        if nextinused == 0 and not prevfreed:
            if hex(nextchunk["addr"]) not in freerecord :
                print("\033[31m confuse in nextchunk 0x%x" % nextchunk["addr"])
            else :
                chunk["size"] += nextchunk["size"]
                del freerecord[hex(nextchunk["addr"])]
        if prevfreed :
            chunk = prevchunk

        if DEBUG :
            print("")
        freerecord[hex(chunk["addr"])] = copy.deepcopy((chunk["addr"],chunk["addr"]+chunk["size"],chunk))
        if hex(chunk["addr"]) in allocmemoryarea :
            del allocmemoryarea[hex(chunk["addr"])]
        if chunk["size"] > 65536 :
            Malloc_consolidate()
        return False


def Malloc_consolidate(): #merge fastbin when malloc a large chunk or free a very large chunk
    global fastbin
    global freerecord
    get_heap_info()
    arch = getarch()
    if arch == "x86-64":
        ptrsize = 8
        word = "gx "
    else :
        ptrsize = 4
        word = "wx "
    freerecord = {}
    get_heap_info()
    freerecord = copy.deepcopy(freememoryarea) 


def getarch():
    data = gdb.execute('show arch',to_string = True)
    arch =  re.search("currently.*",data)
    if arch : 
        if "x86-64" in arch.group() :
            return "x86-64"
        else :
            return  "i386"
    else :
        return "error"


def procmap():
    data = gdb.execute('info proc exe',to_string = True)
    pid = re.search('process.*',data)
    if pid :
        pid = pid.group()
        pid = pid.split()[1]
        maps = open("/proc/" + pid + "/maps","r")
        infomap = maps.read()
        maps.close()
        return infomap
    else :
        return "error"

def iscplus():
    name = gdb.objfiles()[0].filename
    data = subprocess.check_output("readelf -s " + name,shell=True).decode('utf8')
    if "CXX" in data :
        return True
    else :
        return False


def getprocname():
    data = gdb.execute("info proc exe",to_string=True)
    procname = re.search("exe.*",data).group().split("=")[1][2:-1]
    return procname

def libcbase():
    infomap = procmap()
    data = re.search(".*libc.*\.so",infomap)
    if data :
        libcaddr = data.group().split("-")[0]
        return int(libcaddr,16)
    else :
        return 0

def ldbase():
    infomap = procmap()
    data = re.search(".*ld.*\.so",infomap)
    if data :
        ldaddr = data.group().split("-")[0]
        return int(ldaddr,16)
    else :
        return 0

def getheapbase():
    infomap = procmap()
    data = re.search(".*heap\]",infomap)
    if data :
        heapbase = data.group().split("-")[0]
        return int(heapbase,16)
    else :
        return 0


def codeaddr(): # ret (start,end)
    infomap = procmap()
    procname = getprocname()
    pat = ".*" + procname
    data = re.findall(pat,infomap)
    if data :
        codebase = data[0].split("-")[0]
        codeend = data[0].split("-")[1].split()[0]
        return (int(codebase,16),int(codeend,16))
    else :
        return (0,0)

def findsyscall():
    arch = getarch()
    start,end = codeaddr()
    if arch == "x86-64" :
        gdb.execute("find 0x050f " + hex(start) + " " + hex(end) )
    elif arch == "i386":
        gdb.execute("find 0x80cd " + hex(start) + " " + hex(end) )
    else :
        print("error")

def gettls():
    arch = getarch()
    if arch == "i386" :
        vsysaddr = gdb.execute("info functions __kernel_vsyscall",to_string=True).split("\n")[-2].split()[0].strip()
        sysinfo= gdb.execute("find " + vsysaddr,to_string=True).split("\n")[2]
        match = re.search(r"0x[0-9a-z]{8}",sysinfo)
        if match :
            tlsaddr = int(match.group(),16) - 0x10
        else:
            return "error"
        return tlsaddr
    elif arch == "x86-64" :
        gdb.execute("call arch_prctl(0x1003,$rsp-8)")
        data = gdb.execute("x/x $rsp-8",to_string=True)
        return int(data.split(":")[1].strip(),16)
    else:
        return "error"

def getcanary():
    arch = getarch()
    tlsaddr = gettls()
    if arch == "i386" :
        offset = 0x14
        result = gdb.execute("x/x " + hex(tlsaddr + offset),to_string=True).split(":")[1].strip()
        return int(result ,16)   
    elif arch == "x86-64" :
        offset = 0x28
        result = gdb.execute("x/x " + hex(tlsaddr + offset),to_string=True).split(":")[1].strip()
        return int(result,16)
    else :
        return "error"

def puttls():
    print("\033[34m" + "tls : " + "\033[37m" + hex(gettls()))

def putlibc():
    print("\033[34m" + "libc : " + "\033[37m" + hex(libcbase()))

def putheap():
    heapbase = getheapbase()
    if heapbase :
        print("\033[34m" + "heapbase : " + "\033[37m" + hex(heapbase))
    else :
        print("heap not found")

def putld():
    print("\033[34m" + "ld : " + "\033[37m" + hex(ldbase()))

def putcodebase():
    print("\033[34m" + "codebase : " + "\033[37m" + hex(codeaddr()[0]))

def putcanary():
    print("\033[34m" + "canary : " + "\033[37m" + hex(getcanary()))

def off(sym):
    libc = libcbase()
    try :
        symaddr = int(sym,16)
        return symaddr-libc
    except :
        try :
            data = gdb.execute("x/x " + sym ,to_string=True)
            if "No symbol" in data:
                return 0
            else :
                data = re.search("0x.*[0-9a-f] ",data)
                data = data.group()
                symaddr = int(data[:-1] ,16)
                return symaddr-libc
        except :
            return 0

def putoff(sym) :
    symaddr = off(sym)
    if symaddr == 0 :
        print("Not found the symbol")
    else :
        print("\033[34m" + sym  + ":" + "\033[37m" +hex(symaddr))

def got():
    procname = getprocname()
    cmd = "objdump -R "
    if iscplus :
        cmd += "--demangle "
    cmd += procname
    got = subprocess.check_output(cmd,shell=True)[:-2].decode('utf8')
    print(got)

def dyn():
    data = gdb.execute("info proc exe",to_string=True)
    procname = re.search("exe.*",data).group().split("=")[1][2:-1]
    dyn = subprocess.check_output("readelf -d " + procname,shell=True).decode('utf8')
    print(dyn)

def searchcall(sym):
    procname = getprocname()
    cmd = "objdump -d -M intel "
    if iscplus :
        cmd += "--demangle "
    cmd += procname
    try :
        call = subprocess.check_output(cmd
                + "| grep \"call.*" + sym + "@plt>\""  ,shell=True).decode('utf8')
        return call
    except :
        return "symbol not found"

def ispie():
    procname = getprocname()
    result = subprocess.check_output("readelf -h " + procname,shell=True).decode('utf8')
    if re.search("DYN",result):
        return True
    else:
        return False

def abcd(bit):
    s = ""
    for i in range(0x7a-0x41):
        s += chr(0x41+i)*int((int(bit)/8))
    print(s)

def length(bit,pat):
    off = (ord(pat) - 0x41)*(int(bit)/8)
    print(off)

def putfindcall(sym):
    output = searchcall(sym)
    print(output)

def attachprog(procname =None):
    if procname :
        pidlist = subprocess.check_output("pidof " + procname,shell=True).decode('utf8').split()
        gdb.execute("attach " + pidlist[0])
    else :
        procname = gdb.objfiles()[0].filename.split("/")[-1]
        pidlist = subprocess.check_output("pidof " + procname,shell=True).decode('utf8').split()
        gdb.execute("attach " + pidlist[0])  
    if iscplus() :
        gdb.execute("set print asm-demangle on")

def rop():
    procname = getprocname()
    subprocess.call("ROPgadget --binary " + procname,shell=True)


def bcall(sym):
    call = searchcall(sym)
    if "not found" in call :
        print("symbol not found")
    else :
        if ispie():
            codebase,codeend = codeaddr()
            for callbase in call.split('\n')[:-1]: 
                addr = int(callbase.split(':')[0],16) + codebase
                cmd = "b*" + hex(addr)
                print(gdb.execute(cmd,to_string=True))
        else:
            for callbase in  call.split('\n')[:-1]:
                addr = int(callbase.split(':')[0],16)
                cmd = "b*" + hex(addr)
                print(gdb.execute(cmd,to_string=True))

def set_main_arena():
    global main_arena
    global main_arena_off
    offset = off("&main_arena")
    libc = libcbase()
    arch = getarch()
    if arch == "i386":
        main_arena_off = main_arena_off_32
    if offset :
        main_arena_off = offset
        main_arena = libc + main_arena_off
    elif main_arena_off :
        main_arena = libc + main_arena_off
    else :
        print("You need to set main arena address")

def check_overlap(addr,size,data = None):
    if data :
        for key,(start,end,chunk) in data.items() :
            if (addr >= start and addr < end) or ((addr+size) > start and (addr+size) < end ) :
                return chunk,"error"
    else :
        for key,(start,end,chunk) in freememoryarea.items() :
    #    print("addr 0x%x,start 0x%x,end 0x%x,size 0x%x" %(addr,start,end,size) )
            if (addr >= start and addr < end) or ((addr+size) > start and (addr+size) < end ) :
                return chunk,"freed"
        for key,(start,end,chunk) in allocmemoryarea.items() :
    #    print("addr 0x%x,start 0x%x,end 0x%x,size 0x%x" %(addr,start,end,size) )
            if (addr >= start and addr < end) or ((addr+size) > start and (addr+size) < end ) :
                return chunk,"inused" 
    return None,None

def get_top_lastremainder():
    global main_arena
    global fastbinsize
    global top
    global last_remainder
    chunk = {}
    arch = getarch()
    if arch == "x86-64":
        ptrsize = 8
        word = "gx "
    else :
        ptrsize = 4
        word = "wx "
    #get top
    cmd = "x/" + word + hex(main_arena + fastbinsize*ptrsize + 8 )
    chunk["addr"] =  int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
    chunk["size"] = 0
    if chunk["addr"] :
        cmd = "x/" + word + hex(chunk["addr"]+ptrsize*1)
        try :
            chunk["size"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) & 0xfffffffffffffff8
            if chunk["size"] > 0x21000 :
                chunk["memerror"] = "top is broken ?"
        except :
            chunk["memerror"] = "invaild memory"
    top = copy.deepcopy(chunk)
    #get last_remainder
    chunk = {}
    cmd = "x/" + word + hex(main_arena + (fastbinsize+1)*ptrsize + 8 )
    chunk["addr"] =  int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
    chunk["size"] = 0
    if chunk["addr"] :
        cmd = "x/" + word + hex(chunk["addr"]+ptrsize*1)
        try :
            chunk["size"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) & 0xfffffffffffffff8
        except :
            chunk["memerror"] = "invaild memory"
    last_remainder = copy.deepcopy(chunk)

def get_fast_bin():
    global main_arena
    global fastbin
    global fastbinsize
    global freememoryarea
    fastbin = []
    #freememoryarea = []
    arch = getarch()
    if arch == "x86-64":
        ptrsize = 8
        word = "gx "
    else :
        ptrsize = 4
        word = "wx "
    for i in range(fastbinsize-3):
        fastbin.append([])
        chunk = {}
        is_overlap = (None,None)
        cmd = "x/" + word  + hex(main_arena + i*ptrsize + 8)
        chunk["addr"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
        while chunk["addr"] and not is_overlap[0]:
            cmd = "x/" + word + hex(chunk["addr"]+ptrsize*1)
            try :
                chunk["size"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) & 0xfffffffffffffff8
            except :
                chunk["memerror"] = "invaild memory"
                break
            is_overlap = check_overlap(chunk["addr"], (ptrsize*2)*(i+2))
            chunk["overlap"] = is_overlap
            freememoryarea[hex(chunk["addr"])] = copy.deepcopy((chunk["addr"],chunk["addr"] + (ptrsize*2)*(i+2) ,chunk))
            fastbin[i].append(copy.deepcopy(chunk))
            cmd = "x/" + word + hex(chunk["addr"]+ptrsize*2)
            chunk = {}
            chunk["addr"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
        if not is_overlap[0]:
            chunk["size"] = 0
            chunk["overlap"] = None
            fastbin[i].append(copy.deepcopy(chunk))


def trace_normal_bin(chunkhead):
    global main_arena
    global freememoryarea  
    libc = libcbase()
    bins = []
    ptrsize = 4
    word = "wx "
    arch = getarch()
    if arch == "x86-64":
        ptrsize = 8
        word = "gx "
    if chunkhead["addr"] == 0 : # main_arena not initial
        return None
    chunk = {}
    cmd = "x/" + word  + hex(chunkhead["addr"] + ptrsize*2) #fd
    chunk["addr"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) #get fd chunk
    if (chunk["addr"] == chunkhead["addr"]) :  #no chunk in the bin
        if (chunkhead["addr"] > libc) :
            return bins
        else :
            try :
                cmd = "x/" + word + hex(chunk["addr"]+ptrsize*1)
                chunk["size"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) & 0xfffffffffffffff8
                is_overlap = check_overlap(chunk["addr"],chunk["size"])
                chunk["overlap"] = is_overlap
                chunk["memerror"] = "\033[31mbad fd (" + hex(chunk["addr"]) + ")\033[37m"
            except :
                chunk["memerror"] = "invaild memory"
            bins.append(copy.deepcopy(chunk)) 
            return bins
    else :
        try :
            cmd = "x/" + word + hex(chunkhead["addr"]+ptrsize*3)
            bk = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
            cmd = "x/" + word + hex(bk+ptrsize*2)
            bk_fd = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
            if bk_fd != chunkhead["addr"]:
                chunkhead["memerror"] = "\033[31mdoubly linked list corruption {0} != {1} and \033[36m{2}\033[31m is broken".format(hex(chunkhead["addr"]),hex(bk_fd),hex(chunkhead["addr"]))
                bins.append(copy.deepcopy(chunkhead))
                return bins
            fd = chunkhead["addr"]
            chunkhead = {}
            chunkhead["addr"] = bk #bins addr
            chunk["addr"] = fd #first chunk
        except :
            chunkhead["memerror"] = "invaild memory" 
            bins.append(copy.deepcopy(chunkhead))
            return bins
        while chunk["addr"] != chunkhead["addr"] :
            try :
                cmd = "x/" + word + hex(chunk["addr"])
                chunk["prev_size"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) & 0xfffffffffffffff8
                cmd = "x/" + word + hex(chunk["addr"]+ptrsize*1)
                chunk["size"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) & 0xfffffffffffffff8
            except :
                chunk["memerror"] = "invaild memory"
                break
            try :
                cmd = "x/" + word + hex(chunk["addr"]+ptrsize*2)
                fd = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
                if fd == chunk["addr"] :
                    chunk["memerror"] = "\033[31mbad fd (" + hex(fd) + ")\033[37m"
                    bins.append(copy.deepcopy(chunk))
                    break
                cmd = "x/" + word + hex(fd + ptrsize*3)
                fd_bk = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
                if chunk["addr"] != fd_bk :
                    chunk["memerror"] = "\033[31mdoubly linked list corruption {0} != {1} and \033[36m{2}\033[31m or \033[36m{3}\033[31m is broken".format(hex(chunk["addr"]),hex(fd_bk),hex(fd),hex(chunk["addr"]))
                    bins.append(copy.deepcopy(chunk))
                    break
            except :
                chunk["memerror"] = "invaild memory"
                bins.append(copy.deepcopy(chunk))
                break
            is_overlap = check_overlap(chunk["addr"],chunk["size"])
            chunk["overlap"] = is_overlap
            freememoryarea[hex(chunk["addr"])] = copy.deepcopy((chunk["addr"],chunk["addr"] + chunk["size"] ,chunk))
            bins.append(copy.deepcopy(chunk))
            cmd = "x/" + word + hex(chunk["addr"]+ptrsize*2) #find next
            chunk = {}
            chunk["addr"] = fd
    return bins


def get_unsortbin():
    global main_arena
    global unsortbin
    unsortbin = []
    ptrsize = 4
    word = "wx "
    arch = getarch()
    if arch == "x86-64":
        ptrsize = 8
        word = "gx "
    chunkhead = {}
    cmd = "x/" + word + hex(main_arena + (fastbinsize+2)*ptrsize+8)
    chunkhead["addr"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
    unsortbin = trace_normal_bin(chunkhead)


def get_smailbin():
    global main_arena
    global smallbin
    max_smallbin_size = 512
    smallbin = {}
    ptrsize = 4
    word = "wx "
    arch = getarch()
    if arch == "x86-64":
        ptrsize = 8
        word = "gx "
        max_smallbin_size *= 2
    for size in range(ptrsize*4,max_smallbin_size,ptrsize*2):
        chunkhead = {}
        idx = int((size/(ptrsize*2)))-1
        cmd = "x/" + word + hex(main_arena + (fastbinsize+2)*ptrsize+8 + idx*ptrsize*2)  # calc the smallbin index
        chunkhead["addr"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
        bins = trace_normal_bin(chunkhead)
        if bins and len(bins) > 0 :
            smallbin[hex(size)] = copy.deepcopy(bins)


def largbin_index(size):
    arch = getarch()
    if arch == "x86-64":
        if (size >> 6) <= 48 :
            idx = 48 + (size >> 6)
        elif (size >> 9) <= 20 :
            idx = 91 + (size >> 9)
        elif (size >> 12) <= 10:
            idx = 110 + (size >> 12)
        elif (size >> 15) <= 4 :
            idx = 119 + (size >> 15)
        elif (size >> 18) <= 2:
            idx = 124 + (size >> 18)
        else :
            idx = 126
    else :
        if (size >> 6) <= 38 :
            idx = 56 + (size >> 6)
        elif (size >> 9) <= 20 :
            idx = 91 + (size >> 9)
        elif (size >> 12) <= 10:
            idx = 110 + (size >> 12)
        elif (size >> 15) <= 4 :
            idx = 119 + (size >> 15)
        elif (size >> 18) <= 2:
            idx = 124 + (size >> 18)
        else :
            idx = 126
    return idx 


def get_largebin():
    global main_arena
    global largebin
    min_largebin = 512
    largebin = {}
    ptrsize = 4
    idxsize = 56
    word = "wx "
    arch = getarch()
    if arch == "x86-64":
        ptrsize = 8
        idxsize = 48
        word = "gx "
        min_largebin *=2
    for idx in range(64,128):
        chunkhead = {}
        cmd = "x/" + word + hex(main_arena + (fastbinsize+2)*ptrsize + idx*ptrsize*2)  # calc the largbin index
        chunkhead["addr"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
        bins = trace_normal_bin(chunkhead)
        if bins and len(bins) > 0 :
            largebin[idx] = copy.deepcopy(bins)

def get_heap_info():
    global main_arena
    global freememoryarea
    global top
    top = {}
    freememoryarea = {}
    set_main_arena()
    if main_arena :
        if tracelargebin :
            get_largebin()
        get_unsortbin()
        get_smailbin()
        get_fast_bin()
        get_top_lastremainder()


def get_reg(reg):
    cmd = "info register " + reg
    result = int(gdb.execute(cmd,to_string=True).split()[1].strip(),16)
    return result


def trace_malloc():
    global mallocbp
    global freebp
    libc = libcbase()
    arch = getarch()
    if arch == "x86-64" :
        if _int_malloc_off != 0 :
            malloc_addr = libc + _int_malloc_off
            free_addr = libc + _int_free_off
        else :
            malloc_addr = libc + malloc_off
            free_addr = libc + free_off
    else :
        if _int_malloc_off_32 != 0 :
            malloc_addr = libc + _int_malloc_off_32
            free_addr = libc + _int_free_off_32
        else :
            malloc_addr = libc + malloc_off_32
            free_addr = libc + free_off_32

    mallocbp = Malloc_Bp_handler("*" + hex(malloc_addr))
    freebp = Free_Bp_handler("*" + hex(free_addr))
    get_heap_info()

def dis_trace_malloc():
    global mallocbp
    global freebp
    if mallocbp and freebp :   
        mallocbp.delete()
        freebp.delete()
        mallocbp = None
        freebp = None
        allocmemoryarea = {}
 
def set_trace_mode(option="on"):
    global tracemode
    if option == "on":
        tracemode = True
        trace_malloc()
    else :
        tracemode = False
        dis_trace_malloc()

def find_overlap(chunk,bins):
    is_overlap = False
    count = 0
    for current in bins :
        if chunk["addr"] == current["addr"] :
            count += 1
    if count > 1 :
        is_overlap = True
    return is_overlap


def putfastbin():
    ptrsize = 4
    arch = getarch()
    if arch == "x86-64":
        ptrsize = 8
    get_heap_info()
    for i,bins in enumerate(fastbin) :
        cursize = (ptrsize*2)*(i+2)
        print("\033[32m(0x%02x)     fastbin[%d]:\033[37m " % (cursize,i),end = "")
        for chunk in bins :
            if "memerror" in chunk :
                print("\033[31m0x%x (%s)\033[37m" % (chunk["addr"],chunk["memerror"]),end = "")
            elif chunk["size"] != cursize and chunk["addr"] != 0 :
                print("\033[36m0x%x (size error (0x%x))\033[37m" % (chunk["addr"],chunk["size"]),end = "")
            elif chunk["overlap"] and chunk["overlap"][0]:
                print("\033[31m0x%x (overlap chunk with \033[36m0x%x(%s)\033[31m )\033[37m" % (chunk["addr"],chunk["overlap"][0]["addr"],chunk["overlap"][1]),end = "")
            elif chunk == bins[0]  :
                print("\033[34m0x%x\033[37m" % chunk["addr"],end = "")
            else  :
                if print_overlap :
                    if find_overlap(chunk,bins):
                        print("\033[31m0x%x\033[37m" % chunk["addr"],end ="")
                    else :
                        print("0x%x" % chunk["addr"],end = "")
                else :
                    print("0x%x" % chunk["addr"],end = "")
            if chunk != bins[-1]:
                print(" --> ",end = "")
        print("")

def putheapinfo():
    ptrsize = 4
    idxsize = 56
    arch = getarch()
    if arch == "x86-64":
        ptrsize = 8
        idxsize = 48
    putfastbin()
    if "memerror" in top :
        print("\033[35m %20s:\033[31m 0x%x \033[33m(size : 0x%x)\033[31m (%s)\033[37m " % ("top",top["addr"],top["size"],top["memerror"]))
    else :
        print("\033[35m %20s:\033[34m 0x%x \033[33m(size : 0x%x)\033[37m " % ("top",top["addr"],top["size"]))
    print("\033[35m %20s:\033[34m 0x%x \033[33m(size : 0x%x)\033[37m " % ("last_remainder",last_remainder["addr"],last_remainder["size"]))
    if unsortbin and len(unsortbin) > 0 :
        print("\033[35m %20s:\033[37m " % "unsortbin",end="")
        for chunk in unsortbin :
            if "memerror" in chunk :
                print("\033[31m0x%x (%s)\033[37m" % (chunk["addr"],chunk["memerror"]),end = "")
            elif chunk["overlap"] and chunk["overlap"][0]:
                print("\033[31m0x%x (overlap chunk with \033[36m0x%x(%s)\033[31m )\033[37m" % (chunk["addr"],chunk["overlap"][0]["addr"],chunk["overlap"][1]),end = "")
            elif chunk == unsortbin[-1]:
                print("\033[34m0x%x\033[37m \33[33m(size : 0x%x)\033[37m" % (chunk["addr"],chunk["size"]),end = "")
            else :
                print("0x%x \33[33m(size : 0x%x)\033[37m" % (chunk["addr"],chunk["size"]),end = "")
            if chunk != unsortbin[-1]:
                print(" <--> ",end = "")
        print("")
    else :
        print("\033[35m %20s:\033[37m 0x%x" % ("unsortbin",0)) #no chunk in unsortbin
    for size,bins in smallbin.items() :
        idx = int((int(size,16)/(ptrsize*2)))-2 
        print("\033[33m(0x%03x)  %s[%2d]:\033[37m " % (int(size,16),"smallbin",idx),end="")
        for chunk in bins :
            if "memerror" in chunk :
                print("\033[31m0x%x (%s)\033[37m" % (chunk["addr"],chunk["memerror"]),end = "")
            elif chunk["size"] != int(size,16) :
                print("\033[36m0x%x (size error (0x%x))\033[37m" % (chunk["addr"],chunk["size"]),end = "")
            elif chunk["overlap"] and chunk["overlap"][0]:
                print("\033[31m0x%x (overlap chunk with \033[36m0x%x(%s)\033[31m )\033[37m" % (chunk["addr"],chunk["overlap"][0]["addr"],chunk["overlap"][1]),end = "")
            elif chunk == bins[-1]:
                print("\033[34m0x%x\033[37m" % chunk["addr"],end = "")
            else :
                print("0x%x " % chunk["addr"],end = "")
            if chunk != bins[-1]:
                print(" <--> ",end = "")
        print("") 
    for idx,bins in largebin.items():
#        print("\033[33m(0x%03x-0x%03x)  %s[%2d]:\033[37m " % (int(size,16),int(maxsize,16),"largebin",idx),end="")
        print("\033[33m  %15s[%2d]:\033[37m " % ("largebin",idx),end="")
        for chunk in bins :
            if "memerror" in chunk :
                print("\033[31m0x%x (%s)\033[37m" % (chunk["addr"],chunk["memerror"]),end = "")
            elif chunk["overlap"] and chunk["overlap"][0]:
                print("\033[31m0x%x (overlap chunk with \033[36m0x%x(%s)\033[31m )\033[37m" % (chunk["addr"],chunk["overlap"][0]["addr"],chunk["overlap"][1]),end = "")
            elif largbin_index(chunk["size"]) != idx : 
                print("\033[31m0x%x (incorrect bin size :\033[36m 0x%x\033[31m)\033[37m" % (chunk["addr"],chunk["size"]),end = "")
            elif chunk == bins[-1]:
                print("\033[34m0x%x\033[37m \33[33m(size : 0x%x)\033[37m" % (chunk["addr"],chunk["size"]),end = "")
            else :
                print("0x%x \33[33m(size : 0x%x)\033[37m" % (chunk["addr"],chunk["size"]),end = "")
            if chunk != bins[-1]:
                print(" <--> ",end = "")
        print("") 


def putinused():
    print("\033[33m %s:\033[37m " % "inused ",end="")
    for addr,(start,end,chunk) in allocmemoryarea.items() :
        print("0x%x," % (chunk["addr"]),end="")
    print("")
