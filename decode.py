from hashlib import sha256
import base64
import hashlib
import hmac
import os
import struct
import sys

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

#otp = base64.b64decode(sys.argv[1])
#
#mac = otp[0:32]
#nonce = chr(0x00) * 24 + otp[32:40]

parts = sys.argv[1].split('.')
nonce  = base64.b64decode(parts[0])
mac = base64.b64decode(parts[1])

#count = ord(otp[36])
#for i in range(1,4):
#  count = count << 8
#  count = count + ord(otp[36 + i])
#print count

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
