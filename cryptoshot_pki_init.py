#!/usr/bin/env python
"""
Author: DiabloHorn http://diablohorn.wordpress.com
Project: cryptoshot, taking enrypted screenshots
"""
from Crypto.PublicKey import RSA
import struct
import argparse

def appendpublickey(filename,rsapublickey,rsapublickeylen):
    with open(filename,'a+b') as binaryfile:
        binaryfile.write(rsapublickey)
        binaryfile.write(struct.pack('i',rsapublickeylen))
        
def writedatatofile(filename,data):
    f = open (filename,'w')
    f.write(data)
    f.close()
    
def generatersakeypair(keypairsize):
    rsaprivatekey = RSA.generate(keypairsize) 
    rsaprivatekey_pem = rsaprivatekey.exportKey()
    rsapublickey_pem = rsaprivatekey.publickey().exportKey()
    return (rsaprivatekey_pem, rsapublickey_pem)

if __name__ == "__main__":

    parser = argparse.ArgumentParser()        
    parser.add_argument("exefile",help="Executable to which the public key will be appended")
    parser.add_argument("--keysize",type=int,choices=[1024, 2048, 3072, 4096],help="RSA keypair size")
    parser.add_argument("--privkeysave",help="location for storing the private key")
    args = parser.parse_args()

    if args.keysize:
        rsakeysize = args.keysize        
    else:
        rsakeysize = 2048

    if args.privkeysave:
        privkeyoutput = args.privkeysave
    else:
        privkeyoutput = "private.key"
        
    print "Generating RSA keypair of size: %s" % rsakeysize
    rsapriv,rsapub = generatersakeypair(rsakeysize)
    print "Generation done"
    print "Saving private key to: %s" % privkeyoutput    
    writedatatofile(privkeyoutput,rsapriv)
    print "Adding public key to %s" % args.exefile
    appendpublickey(args.exefile,rsapub,len(rsapub))