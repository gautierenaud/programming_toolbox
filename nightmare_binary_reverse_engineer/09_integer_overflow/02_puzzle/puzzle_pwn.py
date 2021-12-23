import z3
import pwn as p

# X * 0x1064deadbeef4601 && 0xffffffffffffffff = 0xD1038D2E07B42569


def s(b: bytes) -> str:
    return b.decode('utf8')


z = z3.Solver()

x = z3.BitVec("0", 64)
z.add((x * 0x1064deadbeef4601) & 0xffffffffffffffff == 0xD1038D2E07B42569)

if z.check() == z3.sat:
    solution = z.model()
    sol_x = solution[x].as_long()
    pwd = s(p.p64(sol_x))

    print('password:', pwd)

    target = p.process(['./puzzle', pwd])
    target.interactive()
else:
    print(f'Failed... {z.check()}')
