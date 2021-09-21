from boxes import *


def gf(a, b):
  c = 0
  while b:
    if b & 1:
      c ^= a
    a = (a << 1) ^ 0x1C3 if a & 0x80 else (a << 1)
    b >>= 1
  return c


def XOR(bseq1: bytes, bseq2: bytes):
    return bytes([a^b for a,b in zip(bseq1,bseq2)])



def S(block: bytes):
    newBlock=[]
    
    for byte in block:
        newBlock.append(Pi[byte])
    
    return bytes(newBlock)
    

def InvS(block: bytes):
    newBlock=[]
    
    for byte in block:
        newBlock.append(InvPi[byte])
    
    return bytes(newBlock)


def l_helper(block: bytes):
    bs=(148,32,133,16,194,192,1,251,1,192,194,16,133,32,148,1)

    c=0
    
    for b,a in zip(bs,block):
        c^=gf(a,b)

    return c


def R(block: bytes):
    lbyte=l_helper(block)
    rb=bytes([lbyte])+block[:-1]

    return rb


def InvR(block: bytes):
    lbyte=l_helper(block[1:]+block[0:1])
    
    return block[1:]+bytes([lbyte])


def L(block: bytes):
    b=block
    
    for _ in range(16):
        b=R(b)

    return b


def InvL(block: bytes):
    b=block
    
    for _ in range(16):
        b=InvR(b)
    
    return b


def F(C: bytes,K: bytes):
    
    t=XOR(C,K)
    t=S(t)
    t=L(t)
    
    return t
    


def KeySchedule(key: bytes):
    
    keys=[]
    
    K1=key[:16]
    K2=key[16:]

    keys.append(K1)
    keys.append(K2)


    C=1
    for _ in range(4):
        for __ in range(8):
            Ci=C.to_bytes(16,'big')
            Ci=L(Ci)

            t=XOR(F(K1,Ci),K2)
            K2=K1
            K1=t
            C+=1
        
        keys.append(K1)
        keys.append(K2)

    return keys
    

def Encrypt(plaintext: bytes, key: bytes):
    subkeys=KeySchedule(key)
    ciphertext=[]
    
    for i in range(0,len(plaintext),16):
        block=plaintext[i:i+16]
        
        for subkey in subkeys[:-1]:
            block=XOR(block,subkey)
            block=S(block)
            block=L(block)
        
        block=XOR(block,subkeys[-1])
        ciphertext.append(block)
        
    return b''.join(ciphertext)    



def Decrypt(ciphertext: bytes, key: bytes):
    subkeys=KeySchedule(key)
    subkeys=subkeys[::-1]
    plaintext=[]

    for i in range(0,len(ciphertext),16):
        block=ciphertext[i:i+16]
        
        for subkey in subkeys[:-1]:
            block=XOR(block,subkey)
            block=InvL(block)
            block=InvS(block)
        
        block=XOR(block,subkeys[-1])
        plaintext.append(block)
        
        
    return b''.join(plaintext)


# print()
    
# a='1122334455667700ffeeddccbbaa9988'
# a=bytes.fromhex(a)


# key='8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef'
# key=bytes.fromhex(key)

# c=Encrypt(a,key)
# print(c.hex())


# p=Decrypt(c,key)
# print(p.hex())

# k=KeySchedule(key)

# for i in k:
    # print(i.hex())

# Ci=1
# Ci=Ci.to_bytes(16,'big')
# print(Ci.hex())
# Ci=R(R(Ci))
# Ci=R(Ci)
# print(Ci.hex())

