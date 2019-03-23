from ecdsa import SigningKey, VerifyingKey, NIST256p
from hashlib import sha3_256
from vm import BYTESIZE
"""
sk = SigningKey.generate(curve=NIST256p) # uses NIST192p
vk = sk.get_verifying_key()
signature = sk.sign("message".encode("utf8"), hashfunc=sha3_256)
print(signature, len(signature))
assert vk.verify(signature, "message".encode("utf8"), hashfunc=sha3_256)
"""

def hashit(byte):
    hsh = sha3_256(byte)
    return hsh.digest()

def wrapint(number, func):
    return fromb(func(tob(number)))

def tob(number):
    return number.to_bytes(BYTESIZE, byteorder="big", signed=False)

def fromb(byte):
    return int.from_bytes(byte, byteorder="big", signed=False)

def genkey():
    sk = SigningKey.generate(curve=NIST256p)
    vk = sk.get_verifying_key()
    return sk.to_string(), vk.to_string()

def verify(key, signature, message):
    vk = VerifyingKey.from_string(key, curve=NIST256p)
    try:
        vk.verify(signature, message, hashfunc=sha3_256)
        return True
    except:
        return False
