import base64
import hmac
import hashlib
from hashlib import sha256

def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv
        lst.append(hv)
    
    return reduce(lambda x,y:x+y, lst)

key_encoded = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
secret_encoded = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

key = base64.b64decode("IiQluaNsRFNfoTKfN8xuSUUCIJ5d3QIy88VOGjo+RFU=")
secret = base64.b64decode("ceI089/UUTtug230x73CG9bi9aeSLGSwJVcVwQRJotA=")

#key = base64.b64decode(key_encoded)
#secret = base64.b64decode(secret_encoded)

# 0x07

message = key + \
    secret + \
    chr(0x08) + \
    chr(0x05) + \
    chr(0x00) + chr(0x00) + \
    chr(0x00) * 8 + \
    chr(0x00) * 3 + \
    chr(0xEE) + \
    chr(0x00) * 4 + \
    chr(0x01) + chr(0x23) + \
    chr(0x00) * 2

signature = base64.b64encode(hmac.new(secret, message, digestmod=hashlib.sha256).digest())

print ""
print(toHex(sha256(message).digest()))
print len(message)
