import argparse
from utils import Encrypt,Decrypt
import sys


parser = argparse.ArgumentParser()
parser.add_argument("target",type=bytes.fromhex)
parser.add_argument("key",type=bytes.fromhex)
parser.add_argument("-d",action="store_true")
args=parser.parse_args()

if len(args.target)!=16:
    print('Target\'s length sholud be a multiple of 16 ')
    sys.exit(1)

if len(args.key)!=32:
    print('Key\'s length sholud be equal to 32 ')
    sys.exit(1)

if not args.d:
    print(Encrypt(args.target,args.key).hex())
else:
    print(Decrypt(args.target,args.key).hex())








