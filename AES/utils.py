from boxes import *


xor=lambda bseq1,bseq2 : bytes(a^b for a,b in zip(bseq1,bseq2))
RotWord= lambda word : word[1:4]+word[0:1]    

def SboxLookup(xy: int):
    x =(xy&0b11110000)>>4
    y = xy&0b00001111
    return Sbox[x][y]


def InvSboxLookup(xy: int):
    x =(xy&0b11110000)>>4
    y = xy&0b00001111
    return InvSbox[x][y]

SubWord= lambda word: bytes(SboxLookup(byte) for byte in word)

def KeyExpansion(key: bytes,Nk,Nr):
    w=[None]*4*(Nr+1)
    
    i=0
    while i<Nk:
        w[i]=key[4*i:4*i+4]
        i+=1
    
    i=Nk
    
    while i<4*(Nr+1):
        temp=w[i-1]
        if i%Nk == 0:
            temp=xor(SubWord(RotWord(temp)),Rcon[i//Nk])
        elif Nk>6 and i%Nk==4:
            temp=SubWord(temp)
        w[i]=xor(w[i-Nk],temp)
        i+=1
    
    return w
    

def ConvertToState(bs:bytes):
    # Converts 16-byte-long sequence in state
    state=[
        [bs[0],bs[4],bs[8],bs[12]],
        [bs[1],bs[5],bs[9],bs[13]],
        [bs[2],bs[6],bs[10],bs[14]],
        [bs[3],bs[7],bs[11],bs[15]]
    ]
    return state
    
def ConvertToAOB(state):
    #Converts state to 16-byte-long array of bytes
    words=[]
    for j in range(4):
        word=[]
        for i in range(4):
            word.append(state[i][j])
        words.append(bytes(word))
      
    return b''.join(words)
    
    
def AddRoundKey(state,subkey):

    newState=[]
    for i in range(4):
        row=[]
        for j in range(4):
            row.append(state[i][j]^subkey[i][j])
        newState.append(row)

    return newState
    

def SubBytes(state):
    for j in range(4):
        for i in range(4):
            state[i][j]=SboxLookup(state[i][j])

    return state


def ROR(a,shift):
    
    for j in range(shift):
        last=a[-1]
        for i in range(len(a)-1,0,-1):
            a[i]=a[i-1]
        a[0]=last
    return a

def ROL(a,shift):
    return ROR(a[::-1],shift)[::-1]


def ShiftRows(state):
    for shift,row in enumerate(state):
        state[shift]=ROL(row,shift)
    
    return state


def MixColumns(state):
    
    row1=[]
    row2=[]
    row3=[]
    row4=[]
    
    
    for j in range(4):
        a=mul02[state[0][j]]^mul03[state[1][j]]^state[2][j]^state[3][j]
        row1.append(a)
        b=state[0][j]^mul02[state[1][j]]^mul03[state[2][j]]^state[3][j]
        row2.append(b)
        c=state[0][j]^state[1][j]^mul02[state[2][j]]^mul03[state[3][j]]
        row3.append(c)
        d=mul03[state[0][j]]^state[1][j]^state[2][j]^mul02[state[3][j]]
        row4.append(d)
    
    return [row1,row2,row3,row4]

    #return newState
    


def Encrypt(plaintext: bytes,key: bytes,Nk,Nr):
    
    subkeyWords=KeyExpansion(key,Nk,Nr)
    subkeys=[b''.join(subkeyWords[i:i+4]) for i in range(0,len(subkeyWords),4)]
    subkeyStates= [ConvertToState(subkey) for subkey in subkeys]
    
    ciphertext=[]
    
    for i in range(0,len(plaintext),16):
        block=plaintext[i:i+16]
        
        state=ConvertToState(block)
        state=AddRoundKey(state,
                          subkeyStates[0]
                          )
        
        for r in range(1,Nr):
            state=SubBytes(state)
            state=ShiftRows(state)
            state=MixColumns(state)
            state=AddRoundKey(state,
                              subkeyStates[r]
                          )
        
        state=SubBytes(state)
        state=ShiftRows(state)
        state=AddRoundKey(state,
                          subkeyStates[Nr]
                          )
        
        
        ciphertext.append(ConvertToAOB(state))
    
    return b''.join(ciphertext).hex()




def InvShiftRows(state):
    for shift,row in enumerate(state):
        state[shift]=ROR(row,shift)
    
    return state

def InvSubBytes(state):
    for j in range(4):
        for i in range(4):
            state[i][j]=InvSboxLookup(state[i][j])

    return state


def InvMixColumns(state):
    row1=[]
    row2=[]
    row3=[]
    row4=[]
    
    
    for j in range(4):
        a=mul0e[state[0][j]]^mul0b[state[1][j]]^mul0d[state[2][j]]^mul09[state[3][j]]
        row1.append(a)
        b=mul09[state[0][j]]^mul0e[state[1][j]]^mul0b[state[2][j]]^mul0d[state[3][j]]
        row2.append(b)
        c=mul0d[state[0][j]]^mul09[state[1][j]]^mul0e[state[2][j]]^mul0b[state[3][j]]
        row3.append(c)
        d=mul0b[state[0][j]]^mul0d[state[1][j]]^mul09[state[2][j]]^mul0e[state[3][j]]
        row4.append(d)
    
    return [row1,row2,row3,row4]



def Decrypt(ciphertext: bytes,key: bytes,Nk,Nr):
    subkeyWords=KeyExpansion(key,Nk,Nr)
    subkeys=[b''.join(subkeyWords[i:i+4]) for i in range(0,len(subkeyWords),4)]
    subkeyStates= [ConvertToState(subkey) for subkey in subkeys]
    subkeyStates=subkeyStates[::-1]
    
    plaintext=[]
    for i in range(0,len(ciphertext),16):
        block=ciphertext[i:i+16]
        
        state=ConvertToState(block)
        state=AddRoundKey(state,
                          subkeyStates[0]
                          )
        state=InvShiftRows(state)
        state=InvSubBytes(state)
        
        for r in range(1,Nr):
            state=AddRoundKey(state,
                              subkeyStates[r]
                          )
            state=InvMixColumns(state)
            state=InvShiftRows(state)
            state=InvSubBytes(state)
            

        state=AddRoundKey(state,
                          subkeyStates[Nr]
                          )

        plaintext.append(ConvertToAOB(state))
        
    return b''.join(plaintext).hex()






