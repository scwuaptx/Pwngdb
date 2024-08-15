source $HOME/Documents/GDB-Plug-in/pwndbg/gdbinit.py
source $HOME/Documents/GDB-Plug-in/Pwngdb/pwngdb.py
source $HOME/Documents/GDB-Plug-in/Pwngdb/angelheap/gdbinit.py

define hook-run
python
import angelheap
angelheap.init_angelheap()
end
end
