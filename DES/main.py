import argparse
from utils import *
from spboxes import *

def validate_ascii_msg(msg):
    if len(msg) and len(msg)%8==0:
        return msg
    else:
        raise argparse.ArgumentTypeError('Message\'s length must be a multiple of 8')

def validate_ascii_key(key):
    if len(key)==8:
        return key
    else:
        raise argparse.ArgumentTypeError('Key\'s len must be equal to 8')

def validate_hex_msg(msg):
    if not msg:
        raise argparse.ArgumentTypeError('Message\'s length must be a multiple of 8')
    msg=msg.strip().split()
    msg=[int(i,16) for i in msg]
    if len(msg) and len(msg)%8==0:
        return bytes(msg)
    else:
        raise argparse.ArgumentTypeError('Message\'s length must be a multiple of 8')
    

def validate_hex_key(key):
    if not key:
        raise argparse.ArgumentTypeError('Message\'s length must be a multiple of 8')
    key=key.strip().split()
    key=[int(i,16) for i in key]
    if len(key)==8:
        return bytes(key)
    else:
        raise argparse.ArgumentTypeError('Key\'s len must be equal to 8')

def hexstr(bs: bytes):
    return ' '.join([hex(byte)[2:] for byte in bs])

if __name__=='__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('msg',metavar='message',help='Plain or cipher text')
    parser.add_argument('key',help='Secret key')
    parser.add_argument('-mh',action='store_true',help='Message is passed in HEX if -mh is specified')
    parser.add_argument('-kh',action='store_true',help='Key is passed in HEX if -kh is specified')
    parser.add_argument('-d',action='store_true',help='Decrypting message if -d is specified')
    args=parser.parse_args()
    
    if args.kh:
        args.key=validate_hex_key(args.key)
    else:
        args.key=validate_ascii_key(args.key)
    
    if args.mh:
        args.msg=validate_hex_msg(args.msg)
    else:
        args.msg=validate_ascii_msg(args.msg)
        
    #print(args)
    
    args.key=args.key if args.kh else args.key.encode('ascii')
    key=KeySchedule(args.key,args.d)
    
    args.msg=args.msg if args.mh else args.msg.encode('ascii')
    msg=bytesToBitvector(args.msg)
    
    print("{} text(ASCII):".format('Plain' if not args.d else 'Cipher'),args.msg.decode('ascii',errors='replace'))
    print("{} text(HEX):".format('Plain' if not args.d else 'Cipher'),hexstr(args.msg))
    print("Key(ASCII):",args.key.decode('ascii',errors='replace'))
    print("Key(HEX):",hexstr(args.key))
    
    result=[]
    for i in range(0,len(msg),64):
        block=msg[i:i+64]
        block=permute(block,IP)
        l,r=block[0:32],block[32:]
        for subkey in key:
            left=r
            right=bitvectorXOR(F(r,subkey),l)
            l=left
            r=right
        block=permute(r+l,IP1)
        result.extend(block)
    
    
    
    result=bitvectorToBytes(result)
    print("{} text(ASCII):".format('Cipher' if not args.d else 'Plain'),result.decode('ascii',errors='replace'))
    print("{} text(HEX):".format('Cipher' if not args.d else 'Plain'),hexstr(result))
    
    
    
    