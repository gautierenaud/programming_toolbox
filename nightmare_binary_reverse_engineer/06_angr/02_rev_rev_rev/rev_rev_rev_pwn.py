from ctypes import c_uint8


def printBytesAsHex(raw_bytes):
    print(list(map(hex, raw_bytes)))

def printBytesAsString(raw_bytes):
    print(bytes(raw_bytes).decode('utf8'))


goal = [0x41, 0x29, 0xd9, 0x65, 0xa1, 0xf1, 0xe1, 0xc9, 0x19, 0x09, 0x93, 0x13, 0xa1, 0x09, 0xb9,
        0x49, 0xb9, 0x89, 0xdd, 0x61, 0x31, 0x69, 0xa1, 0xf1, 0x71, 0x21, 0x9d, 0xd5, 0x3d, 0x15, 0xd5]

printBytesAsHex(goal)

# flip bits (0xff for a bitmask on 8 bits)
goal_rev = list(map(lambda x: x ^ 0xff, goal))
print(goal_rev)


def transfo3_rev(x):
    #  bVar1 >> 4 | bVar1 << 4 : apply the same to revert
    x = ((x >> 4) | (x << 4)) & 0xff
    #  bVar1 >> 2 & 0x33U | bVar1 & 0x33U << 2: apply same to revert
    x = (((x >> 2) & 0x33) | ((x & 0x33) << 2)) & 0xff
    #  local_8 >> 1 & 0x55U | (*local_8 & 0x55) << 1: apply same to revert
    x = (((x >> 1) & 0x55) | ((x & 0x55) << 1)) & 0xff
    return x


goal_rev_rev = list(map(transfo3_rev, goal_rev))
printBytesAsString(goal_rev_rev)

# reverse the list
goal_rev_rev.reverse()
printBytesAsString(goal_rev_rev)

# The rest is just replacing a newline with a null byte, so we don't care
printBytesAsString(goal_rev_rev)
