# Pwngdb ❤️ pwndbg

## How to install

1. Put `pwngdb.py` and `angelheap.py` into `/path/to/pwndbg/pwndbg/`

2. Put `commands/pwngdb.py` and `commands/angelheap.py` into `/path/to/pwndbg/pwndbg/commands/`

3. Add `import pwndbg.commands.pwngdb` and `import pwndbg.commands.angelheap` into `/path/to/pwndbg/pwndbg/__init__.py`

You can use these commands to install it:

```shell
#!/bin/bash
# You need to change the `/path/to/pwdbg` to your pwndbg location

pwndbg='/path/to/pwndbg'

cp pwngdb.py $pwndbg/pwndbg/pwngdb.py
cp angelheap.py $pwndbg/pwndbg/angelheap.py

cp commands/pwngdb.py $pwndbg/pwndbg/commands/pwngdb.py
cp commands/angelheap.py $pwndbg/pwndbg/commands/angelheap.py

sed -i -e '/import pwndbg.commands.xor/a import pwndbg.commands.pwngdb' $pwndbg/pwndbg/__init__.py
sed -i -e '/import pwndbg.commands.xor/a import pwndbg.commands.angelheap' $pwndbg/pwndbg/__init__.py
```

## Note

To avoid the conflict with pwndbg, some commands will be different or be removed.

1. `got` will be renamed to `objdump_got`

2. `canary` will be removed since pwndbg already has `canary` command

## TODO

- [ ] Use more pwndbg API if possible instead of using `gdb.execute` (see [developer notes of pwndbg](https://github.com/pwndbg/pwndbg/blob/dev/DEVELOPING.md))
