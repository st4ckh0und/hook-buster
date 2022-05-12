import sys

def rotr(x, s):
    return ((x >> s) | (x << (32 - s))) & 0xffffffff

if len(sys.argv) != 2:
    print("Usage: {} <string>".format(sys.argv[0]))
else:
    hash = 0

    for c in sys.argv[1]:
        hash = rotr(hash, 13)
        hash += ord(c)
    
    print(hex(hash))