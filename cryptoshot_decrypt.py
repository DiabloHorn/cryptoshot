#!/usr/bin/env python
"""
Author: DiabloHorn http://diablohorn.wordpress.com
Project: cryptoshot, taking enrypted screenshots
"""
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA
from Crypto import Random
import struct
import sys
import ntpath

"""
#debugging purposes only
def printhex(data):
    for character in data:
      print character.encode('hex'),
    print ""
"""

def parsefile(encryptedfile):
    file = open(encryptedfile,"rb")
    encryptedkeysize = struct.unpack('i',file.read(4))[0]
    encryptedkeys = file.read(encryptedkeysize)
    encryptedscreenshot = file.read()
    file.close()
    return (encryptedkeys,encryptedscreenshot)

def getprivatersakey(privatekeyfile):
    file = open(privatekeyfile,'r')
    rsaprivatekeystring = file.read()
    file.close()
    return RSA.importKey(rsaprivatekeystring)

def decrypt_rsa(data,key):
    dsize = SHA.digest_size
    sentinel = Random.new().read(48+dsize)
    cipher = PKCS1_v1_5.new(key)    
    return cipher.decrypt(data,sentinel)

def decrypt_aes(encrypted, key, IV):
    aes = AES.new(key, AES.MODE_CBC, IV)
    return aes.decrypt(encrypted)

def savescreenshot(filename, data):
    file = open(filename+".bmp","wb")
    file.write(data)
    file.close()    

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("encryptedscreenshot",help="screenshot(s) to decrypt",nargs='+')
    parser.add_argument("rsaprivatekey",help="RSA private key file")    
    args = parser.parse_args()

    print "Importing private rsa key %s" % args.rsaprivatekey
    rsaprivatekey = getprivatersakey(args.rsaprivatekey)
    for encshot in args.encryptedscreenshot:
        print "Parsing encrypted screenshot %s" % encshot
        encaeskeys,encdata = parsefile(encshot)
        print "Decrypting aes key and iv"
        aeskeys = decrypt_rsa(encaeskeys,rsaprivatekey)
        print "Decrypting screenshot"
        decshot = decrypt_aes(encdata,aeskeys[0:32],aeskeys[32:])
        print "Saving decrypted screenshot"
        savescreenshot(ntpath.basename(encshot), decshot)