#!/usr/bin/env python
"""
Author: DiabloHorn http://diablohorn.wordpress.com
Project: cryptoshot, taking enrypted screenshots
"""
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA512
import struct
import sys
import ntpath
import argparse

#debugging purposes only
def printhex(data):
    for character in data:
      print character.encode('hex'),
    print ""


def parsefile(encryptedfile):
    file = open(encryptedfile,"rb")
    encryptedkeysize = struct.unpack('i',file.read(4))[0]
    encryptedkeys = file.read(encryptedkeysize)
    encryptedhmackey = file.read(encryptedkeysize)
    hmac = file.read(64)
    encryptedscreenshot = file.read()
    file.close()
    return (encryptedkeys,encryptedhmackey,hmac,encryptedscreenshot)

def getprivatersakey(privatekeyfile):
    file = open(privatekeyfile,'r')
    rsaprivatekeystring = file.read()
    file.close()
    return RSA.importKey(rsaprivatekeystring)

def decrypt_rsa(data,rsakey):
    cipher = PKCS1_OAEP.new(rsakey,label="cryptoshot")    
    return cipher.decrypt(data)

def decrypt_aes(encrypted, key, IV):
    aes = AES.new(key, AES.MODE_CBC, IV)
    return aes.decrypt(encrypted)

def ishmac_ok(hmackey,hmac,encdata):
    h = HMAC.new(hmackey,digestmod=SHA512)
    h.update(encdata)
    if hmac == h.digest():
        return True
    else:
        return False
        
def savescreenshot(filename, data):
    file = open(filename+".bmp","wb")
    file.write(data)
    file.close()    

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("encryptedscreenshot",help="screenshot(s) to decrypt",nargs='+')
    parser.add_argument("--rsaprivatekey",help="RSA private key file")    
    args = parser.parse_args()

    if args.rsaprivatekey:
        rsaprivatekey = getprivatersakey(args.rsaprivatekey)
        print "Importing private rsa key %s" % args.rsaprivatekey
    else:
        rsaprivatekey = getprivatersakey("private.key")
        print "Importing private rsa key private.key"    
    
    for encshot in args.encryptedscreenshot:
        print "Parsing encrypted screenshot %s" % encshot
        encaeskeys,enchmac,hmac,encdata = parsefile(encshot)
        print "Decrypting aes key and iv"
        aeskeys = decrypt_rsa(encaeskeys,rsaprivatekey)
        print "Decrypting hmac key"
        hmackey = decrypt_rsa(enchmac,rsaprivatekey)
        print "Verifying hmac"
        if ishmac_ok(hmackey,hmac,encdata):
            print "Decrypting screenshot"
            decshot = decrypt_aes(encdata,aeskeys[0:32],aeskeys[32:])
            print "Saving decrypted screenshot"
            savescreenshot(ntpath.basename(encshot), decshot)
        else:
            print "Verifying hmac failed"         