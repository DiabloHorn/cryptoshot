from Crypto.Cipher import AES
import struct

def printhex(data):
    for character in data:
      print character.encode('hex'),
    print ""
    
def decrypt(encrypted, key, IV):
    aes = AES.new(key, AES.MODE_CBC, IV)
    return aes.decrypt(encrypted)

if __name__ == "__main__":
    f = open("Release\\screen.bmp", "rb")
    aeskey = f.read(32)
    aesiv = f.read(16)
    aesencrypted = f.read()
    f.close()
    bmp = open("unencrypted.bmp","wb")
    bmp.write(decrypt(aesencrypted,aeskey,aesiv))
    bmp.close()