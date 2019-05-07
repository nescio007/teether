from sha3 import keccak_256


def sha3(data):
    return keccak_256(data).digest()


TT256 = 2 ** 256
TT256M1 = 2 ** 256 - 1
TT255 = 2 ** 255
SECP256K1P = 2 ** 256 - 4294968273


def big_endian_to_int(x):
    return int.from_bytes(x, byteorder='big')


def int_to_big_endian(v):
    return v.to_bytes(length=(v.bit_length()+7)//8, byteorder='big')


def to_string(value):
    return str(value)


def bytearray_to_bytestr(value):
    return bytes(value)


def encode_int32(v):
    return int_to_big_endian(v).rjust(32, b'\x00')


def bytes_to_int(value):
    return big_endian_to_int(bytes(value))


def bytearray_to_int(value):
    return bytes_to_int(bytearray_to_bytestr(value))


def is_pow2(x):
    return x and not x & (x - 1)


def log2(x):
    if not is_pow2(x):
        raise ValueError("%d is not a power of 2!" % x)
    i = -1
    while x:
        x >>= 1
        i += 1
    return i


def to_signed(i):
    return i if i < TT255 else i - TT256



class Denoms:
    def __init__(self):
        self.wei = 1
        self.babbage = 10 ** 3
        self.ada = 10 ** 3
        self.kwei = 10 ** 6
        self.lovelace = 10 ** 6
        self.mwei = 10 ** 6
        self.shannon = 10 ** 9
        self.gwei = 10 ** 9
        self.szabo = 10 ** 12
        self.finney = 10 ** 15
        self.mether = 10 ** 15
        self.ether = 10 ** 18
        self.turing = 2 ** 256 - 1


denoms = Denoms()


def unique(l):
    last = None
    for i in l:
        if i != last:
            yield i
        last = i


def is_subseq(a, b):
    a = tuple(a)
    b = tuple(b)
    # True iff a is a subsequence (not substring!) of b
    p = 0
    for x in a:
        try:
            p = b.index(x, p) + 1
        except ValueError:
            return False
    return True


def is_substr(a, b):
    a = tuple(a)
    b = tuple(b)
    # True iff a is a substring of b
    p = 0
    l = len(a)
    while True:
        try:
            p = b.index(a[0], p)
            if b[p:p + l] == a:
                return True
            p += 1
        except ValueError:
            break
    return False
