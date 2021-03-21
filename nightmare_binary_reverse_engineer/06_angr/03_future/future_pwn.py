# print the matrix indexes corresponding to each letter's index
from z3 import *
for i in range(25):
    m = (i * 2) % 25
    f = (i * 7) % 25
    print(f'mat[{m // 5}][{m % 5}] = str[{f}]')


# input z3 has control over
inp = []
for i in range(25):
    b = BitVec(str(i), 8)
    inp.append(b)

h, l = 5, 5
mat = [[0 for i in range(l)] for j in range(h)]
# this is a copy-paste of the matrix printed at the beginning of this program
mat[0][0] = inp[0]
mat[0][2] = inp[7]
mat[0][4] = inp[14]
mat[1][1] = inp[21]
mat[1][3] = inp[3]
mat[2][0] = inp[10]
mat[2][2] = inp[17]
mat[2][4] = inp[24]
mat[3][1] = inp[6]
mat[3][3] = inp[13]
mat[4][0] = inp[20]
mat[4][2] = inp[2]
mat[4][4] = inp[9]
mat[0][1] = inp[16]
mat[0][3] = inp[23]
mat[1][0] = inp[5]
mat[1][2] = inp[12]
mat[1][4] = inp[19]
mat[2][1] = inp[1]
mat[2][3] = inp[8]
mat[3][0] = inp[15]
mat[3][2] = inp[22]
mat[3][4] = inp[4]
mat[4][1] = inp[11]
mat[4][3] = inp[18]

# do the computations corresponding to genAuthString
auth = [0] * 19
auth[0] = mat[4][4] + mat[0][0]
auth[1] = mat[0][2] + mat[2][1]
auth[2] = mat[4][1] + mat[4][2]
auth[3] = mat[3][1] + mat[1][3]
auth[4] = mat[1][2] + mat[3][4]
auth[5] = mat[2][3] + mat[1][0]
auth[6] = mat[2][0] + mat[2][4]
auth[7] = mat[0][3] + mat[3][3] + mat[3][2]
auth[8] = mat[0][1] + mat[0][4] + mat[4][0]
auth[9] = mat[2][0] + mat[3][3]
auth[10] = mat[1][2] + mat[4][0]
auth[0xb] = mat[4][1] + mat[0][4]
auth[0xc] = mat[0][2] + mat[0][3]
auth[0xd] = mat[2][0] + mat[3][0]
auth[0xe] = mat[1][2] + mat[1][4]
auth[0xf] = mat[2][3] + mat[4][3]
auth[0x10] = mat[0][2] + mat[2][2]
auth[0x11] = mat[4][1] + mat[1][1]

z = Solver()
enc = [0x8b, 0xce, 0xb0, 0x89,
       0x7b, 0xb0, 0xb0, 0xee,
       0xbf, 0x92, 0x65, 0x9d,
       0x9a, 0x99, 0x99, 0x94,
       0xad, 0xe4]

# create z3 constrains about the output
# equal to corresponding enc value
for i in range(len(enc)):
    z.add(auth[i] == enc[i])
# can be interpreted as ascii character
for i in range(25):
    z.add(inp[i] > 32)
    z.add(inp[i] < 127)

if z.check() == sat:
    solution = z.model()
    flag = ""
    for i in inp:
        flag += chr(int(str(solution[i])))
    print(f'Flag: {flag}')
else:
    print(f'Failed... {z.check()}')
