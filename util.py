import struct
from math import ceil
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


class Buffer:

    def __init__(self, buf=b""):
        self.buf = buf
        self.pos = 0

    def len(self):
        return len(self.buf)

    def get_int(self):
        result = int.from_bytes(self.buf[self.pos:self.pos+4], byteorder="little")
        self.pos += 4
        return result


def decrypt_xtea(v1, v2, key, n=32):
    delta = 0x9E3779B9
    mask = 0xFFFFFFFF
    summ = (delta * n) & mask  # полный копипаст из steamless
    for i in range(n):
        v2 = (v2 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (summ + key[summ >> 11 & 3]))) & mask
        summ = (summ - delta) & mask
        v1 = (v1 - (((v2 << 4 ^ v2 >> 5) + v2) ^ (summ + key[summ & 3]))) & mask
    return v1, v2


def drmp_decrypt(data, key):
    buff = Buffer(data)
    buff_out = b""
    v1 = 0x55555555
    v2 = 0x55555555

    for i in range(int(ceil(buff.len()/8))):
        d1, d2 = buff.get_int(), buff.get_int()
        tmp_1, tmp_2 = decrypt_xtea(d1, d2, key)
        buff_out += struct.pack("<I", tmp_1 ^ v1) + struct.pack("<I", tmp_2 ^ v2)
        v1, v2 = d1, d2

    return buff_out


def steam_xor(data, key=0):
    buff = Buffer(data)
    buff_out = b""

    if key == 0:
        key = buff.get_int()
    for i in range(int((buff.len() - buff.pos) / 4)):  # исходим из того, что всегда кратное 4
        val = buff.get_int()
        buff_out += struct.pack("<I", key ^ val)
        key = val
    return buff_out, key


def decrypt_code(data, AES_Key, AES_IV):
    aes_key = b""
    aes_iv = b""
    for i in AES_Key:
        aes_key += i.to_bytes(1, byteorder="little")
    for i in AES_IV:
        aes_iv += i.to_bytes(1, byteorder="little")

    aes = AES.new(aes_key, AES.MODE_ECB)
    new_iv = aes.decrypt(aes_iv)
    aes = AES.new(aes_key, AES.MODE_CBC, new_iv)
    data = aes.decrypt(data)

    return unpad(data, 16)
