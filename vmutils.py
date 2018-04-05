def conv(array):
    return sum([[int(i) for i in element.to_bytes(4, byteorder="big", signed=False)] for element in array], [])

import zlib
import base64
import struct

def minify(state):
    byte = conv(state)
    bytearr = bytearray(byte)
    #bytearr = struct.pack(">I" % (len(byte)), byte)
    compressed = zlib.compress(bytearr)
    #print("Uncompressed:", len(bytearr), "Compressed:", len(compressed))

    #hex_string = "".join("%02x" % b for b in compressed)
    #print("Hex:", hex_string, len(hex_string))

    b64c = base64.b64encode(compressed)

    return b64c

def maxify(b64c):
    compressed = base64.b64decode(b64c)
    bytearr = zlib.decompress(compressed)
    array = struct.unpack(">%iI" % (len(bytearr)//4), bytearr)
    return list(array)

"""
minified = minify(state)
maxified = maxify(minified)

print("Base64:", minified, len(minified))

assert state == maxified
"""
