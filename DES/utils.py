import spboxes

def bytesToBitvector(bs: bytes)->list:
    return [1 if byte&(0b10000000>>i) else 0  for byte in bs for i in range(8)]
    
def bitvectorToBytes(bv: list)->bytes:
    bs=[]
    for i in range(0,len(bv),8):
        byte=0
        for i,bit in enumerate(bv[i:i+8]):
            byte|=bit<<(7-i)
        bs.append(byte)
    return bytes(bs)

def bitvectorToStr(bv):
    return ''.join([str(bit) for bit in bv])

def permute(bv: list,pmt_rule: list)->list:
    bvpmt=[None]*len(pmt_rule)
    
    for dest,src in enumerate(pmt_rule):
        bvpmt[dest]=bv[src-1]
        
    return bvpmt

def bitvectorXOR(bv1,bv2):
    return [ bv1[i]^bv2[i] for i in range(len(bv1))]

def sboxlookup(input,sbox):
    row=(input[0]<<1)|input[5]
    column=(input[1]<<3)|(input[2]<<2)|(input[3]<<1)|(input[4])
    return [1 if sbox[row][column]&(0b1000>>i) else 0 for i in range(4)]

def F(rblock,key):
    rblock=permute(rblock,spboxes.E)
    rblock=bitvectorXOR(rblock,key)
    sboxresult=[]
    for sbox_id,i in enumerate(range(0,48,6)):
        sboxinput=rblock[i:i+6]
        sboxoutput=sboxlookup(sboxinput,spboxes.sboxes[sbox_id])
        sboxresult.extend(sboxoutput)
    return permute(sboxresult,spboxes.P)



class KeySchedule():

    def __init__(self,key: bytes,decrypt=False):
        keybv=bytesToBitvector(key)
        pc1bv=permute(keybv,spboxes.PC1)
        self._c0,self._d0=pc1bv[0:28],pc1bv[28:]
        self._decrypt=decrypt
        self._current=0
        self._ci,self._di=None,None
        
    
    def __iter__(self):
        self._ci=self._c0.copy()
        self._di=self._d0.copy()
        self._current=0
        return self
    
    def __next__(self)->list:
        self._current+=1
        if self._current>16:
            self._current=0
            self._ci,self._di=None,None
            raise StopIteration
        
        if not self._decrypt:
            #encryption
            self._ci=KeySchedule.ROL(
                                    self._ci,
                                    KeySchedule._encryptRotations[self._current]
                                    )
            self._di=KeySchedule.ROL(
                                    self._di,
                                    KeySchedule._encryptRotations[self._current]
                                    )
        else:
            #decryption
            self._ci=KeySchedule.ROR(
                                    self._ci,
                                    KeySchedule._decryptRotations[self._current]
                                    )
            self._di=KeySchedule.ROR(
                                    self._di,
                                    KeySchedule._decryptRotations[self._current]
                                    )

        return permute(self._ci+self._di,spboxes.PC2)
        
    @property
    def current(self):
        return self._current
    
    @staticmethod
    def ROL(bv: list,shift: int):
        for _ in range(shift):
            first=bv[0]
            for i in range(len(bv)-1):
                bv[i]=bv[i+1]
            bv[len(bv)-1]=first
        return bv
    
    @staticmethod
    def ROR(bv: list,shift: int):
        for _ in range(shift):
            last=bv[len(bv)-1]
            for i in range(len(bv)-1,0,-1):
                bv[i]=bv[i-1]
            bv[0]=last
        return bv
        
    _encryptRotations={1:1,2:1,3:2,4:2,5:2,6:2,7:2,8:2,9:1,10:2,11:2,12:2,13:2,14:2,15:2,16:1}
    _decryptRotations={1:0,2:1,3:2,4:2,5:2,6:2,7:2,8:2,9:1,10:2,11:2,12:2,13:2,14:2,15:2,16:1}


