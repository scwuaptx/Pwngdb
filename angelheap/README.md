 angelheap
===============
All the heap features (`heapinfo`, `tracemalloc`...) have been seperated from Pwngdb and integrated into an independent module, so everyone can use these features by adding the following lines into their own `.gdbinit`:
```
source ~/Pwngdb/angelheap/gdbinit.py

define hook-run
python
import angelheap
angelheap.init_angelheap()
end
end
``` 
