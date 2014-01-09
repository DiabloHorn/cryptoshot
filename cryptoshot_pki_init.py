from Crypto.PublicKey import RSA
import struct

#http://stackoverflow.com/questions/3504955/using-rsa-in-python
if __name__ == "__main__":
    rsaprivatekey = RSA.generate(4096) #if changed, adjust C accordingly
    rsaprivatekey_pem = rsaprivatekey.exportKey()
    rsapublickey_pem = rsaprivatekey.publickey().exportKey()
    rsapublickeysize = len(rsapublickey_pem)
    print rsapublickeysize
    print rsapublickey_pem
    with open('Release\\cryptoshot_cmd.exe','a+b') as binaryfile:
        binaryfile.write(rsapublickey_pem)
        binaryfile.write(struct.pack('i',rsapublickeysize))