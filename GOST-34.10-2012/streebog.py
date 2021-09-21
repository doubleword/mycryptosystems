from boxes import *


def XOR(bseq1: bytes,bseq2: bytes):
   return bytes(a^b for a,b in zip(bseq1,bseq2))


def S(vect: bytes):
    assert len(vect)==64
    newVec=[]
    
    for byte in vect:
        newVec.append(Pi[byte])
    
    return bytes(newVec)



def P(vect: bytes):
    newVec=[]
    
    for i in Tau:
        newVec.append(vect[i])

    
    return bytes(newVec)

def BytesToBitVector(vect: bytes):
    # Big - endian
    bitvector=[]
    for byte in vect:
        for i in range(8):
            bit=1 if byte&(0b10000000>>i) else 0
            bitvector.append(bit)
    return bitvector

def L(vect: bytes):
    newVec=[]

    portions=[]

    for i in range(0,len(vect),8):
        portions.append(vect[i:i+8])
    
    for portion in portions:
        newPortion=0
        portion=BytesToBitVector(portion)
        
        for i,bit in enumerate(portion):
            newPortion^= bit*A[i]
        
        newVec.append(newPortion.to_bytes(8,'big'))
        
    return b''.join(newVec)
        


def KeySchedule(K: bytes,i: int):
    K=XOR(K,bytes(C[i]))
    K=S(K)
    K=P(K)
    K=L(K)
    
    return K



def E(K,m):
    #print(K.hex())
    state=XOR(K,m)
    
    for i in range(12):
        state = S(state)
        
        state = P(state)
        state = L(state)
        #print(state.hex())
        #print()
        K=KeySchedule(K, i)
        #print(K.hex())
        state=XOR(state,K)
        
    #print(state.hex())
    #sys.exit(1)
 
    return state






def g(N: bytes,m: bytes,h: bytes):
    K=XOR(h,N)
    K=S(K)
    
    K=P(K)
    
    K = L(K)
    

    t = E(K, m)
    
    
    
    t=XOR(h,t)
    G=XOR(t,m)
    
    return G
    

def STREEBOG(M: bytes, hash_len):
    #print(len(M))
    if hash_len!=512 and hash_len!=256:
        raise RuntimeError("Hash length of %d is not supported"%hash_len)
    
    MODULUS=2**512
    
    h=b'\x00'*64 if hash_len==512 else b'\x01'*64
    N=b'\x00'*64
    Z=b'\x00'*64
    
    while len(M)>=64:
        #print(hit)
        m=M[-64::]
        h=g(N,m,h)
        
        #print(h.hex())
        #print()
        
        N=(int.from_bytes(N,'big')+512)%MODULUS
        N=N.to_bytes(64,'big')
        
        Z=(int.from_bytes(Z,'big')+int.from_bytes(m,'big'))%MODULUS
        Z=Z.to_bytes(64,'big')
        
        M=M[0:-64]

    m=b'\x00'*(64-len(M)-1)+b'\x01'+M
    #assert(len(m)==64)
    

    h=g(N,m,h)
    
    #print(h.hex())
    
    N=(int.from_bytes(N,'big')+len(M)*8)%MODULUS
    N=N.to_bytes(64,'big')
    
    #print(N.hex())
    
    
    Z=(int.from_bytes(Z,'big')+int.from_bytes(m,'big'))%MODULUS
    Z=Z.to_bytes(64,'big')

    #print(Z.hex())


    ba=b'\x00'*64
    h=g(ba,N,h)
    #print(h.hex())
    h=g(ba,Z,h)
    #print(h.hex())
    
    return h if hash_len==512 else h[:32]



# из ГОСТа пример №1
# msg=bytes.fromhex('323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130')

# print(STREEBOG(msg,512).hex())
# print(STREEBOG(msg,256).hex())

#print()
 #fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1
# из ГОСТа пример №2
# msg='fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1'
# msg=bytes.fromhex(msg)
# print(STREEBOG(msg,512).hex())
# print(STREEBOG(msg,256).hex())


