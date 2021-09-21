
from utils import Encrypt, Decrypt

import argparse
import sys

# Block size = 128 bit (16 bytes)
# Key size = 128/192/256 bit (16/24/32 bytes)
# Rounds = 10/12/14
# Subkeys = 11/13/15



parser = argparse.ArgumentParser()
parser.add_argument("target",type=bytes.fromhex)
parser.add_argument("key",type=bytes.fromhex)
parser.add_argument("-d",action="store_true")
args=parser.parse_args()

Nk=None
Nr=None

if len(args.key)==16:
    Nk=4
    Nr=10
elif len(args.key)==24:
    Nk=6
    Nr=12
elif len(args.key)==32:
    Nk=8
    Nr=14
    
if len(args.target)%16!=0:
    print('Target\'s length sholud be a multiple of 16 ')
    sys.exit(1)
    
if not args.d:
    print(Encrypt(args.target,args.key,Nk,Nr))
else:
    print(Decrypt(args.target,args.key,Nk,Nr))