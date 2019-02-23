from hashlib import sha256
import base64
import hashlib
import hmac
import os
import sys

print sys.argv

def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv
        lst.append(hv)
    
    return reduce(lambda x,y:x+y, lst)

key = base64.b64decode(os.environ.get("CRYPT_KEY"))
slot = 0 
nonce = base64.b64decode(sys.argv[1])
mac = base64.b64decode(sys.argv[2])

message = key + \
    nonce + \
    chr(0x08) + \
    chr(0x05) + \
    chr(slot) + chr(0x00) + \
    chr(0x00) * 8 + \
    chr(0x00) * 3 + \
    chr(0xEE) + \
    chr(0x00) * 4 + \
    chr(0x01) + chr(0x23) + \
    chr(0x00) * 2

if sha256(message).digest() == mac:
  print "YES!"
else:
  print "NO :("
