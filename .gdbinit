source ~/peda/peda.py
source ~/pwngdb.py

define libc
	python putlibc()
end
define findfmt
	python findfmt()
end

define ld
	python putld()
end

define codebase
	python putcodebase()
end

define off
	python putoff("$arg0")
end
define got
	python got()
end
define dyn
	python dyn()
end
define rdbg
	target remote localhost:1234
end
define findcall
	python putfindcall("$arg0")
end
define bcall
	python bcall("$arg0")
end
define abcd
	python abcd("$arg0")
end
define length
	python length("$arg0","$arg1")
end

define tls
	python puttls()
end

define canary
	python putcanary()
end

define syscall
	python findsyscall()
end

define rop
	python rop()
end

define attprog
	python attachprog("$arg0")
end

define heap
	python putheap()
end

define fastbin
	python putfastbin()
end

define heapinfo
	python putheapinfo()
end
define tracemode
	python tracemode("$arg0")
end

define reg
	python get_reg("$arg0")
end

define tracemalloc
	python set_trace_mode("$arg0")
end

define inused
	python putinused()
end
