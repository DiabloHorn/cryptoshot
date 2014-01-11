from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA
from Crypto import Random
import struct

def printhex(data):
    for character in data:
      print character.encode('hex'),
    print ""
    
def decrypt(encrypted, key, IV):
    aes = AES.new(key, AES.MODE_CBC, IV)
    return aes.decrypt(encrypted)

if __name__ == "__main__":
    file = open("private.key", "r")
    privatekeystring = file.read()
    file.close()    
    f = open("Release\\screen.enc", "rb")
    pubcryptsize = struct.unpack('i',f.read(4))[0]
    pubcrypt = f.read(pubcryptsize)
    aesencrypted = f.read()
    f.close()
    dsize = SHA.digest_size
    sentinel = Random.new().read(48+dsize)
    privatekey = RSA.importKey(privatekeystring)
    cipher = PKCS1_v1_5.new(privatekey)
    
    plaintextkeydata = cipher.decrypt(pubcrypt,sentinel)
    aeskey = plaintextkeydata[0:32]
    aesiv = plaintextkeydata[32:]
    bmp = open("unencrypted.bmp","wb")
    bmp.write(decrypt(aesencrypted,aeskey,aesiv))
    bmp.close()    
    """
    f = open("Release\\screen.bmp", "rb")
    aeskey = f.read(32)
    aesiv = f.read(16)
    aesencrypted = f.read()
    f.close()
    bmp = open("unencrypted.bmp","wb")
    bmp.write(decrypt(aesencrypted,aeskey,aesiv))
    bmp.close()
    """