from sage.all import *
from streebog import STREEBOG as Hash
import random

def sign(p,a,b,m,q, P: tuple, d, msg: bytes):
    E=EllipticCurve(GF(p),[a,b])
    P=E(P)
    
    l=0
    if (q>2**254) and (q<2**256):
        l=256
    elif (q>2**508) and (q<2**512):
        l=512

    h=Hash(msg,l)
    
    alpha=int.from_bytes(h,'big')
    e=alpha%q
    if not e:
        e=1
    
    r=0
    s=0
    while not s:
        k=random.randint(1,q-1)
        C=k*P
        r=int(C.xy()[0])%q
        
        if not r:
            continue
        
        s=(r*d+k*e)%q

    return r.to_bytes(l//8,'big') + s.to_bytes(l//8,'big')
    

# | Signature | Msg |


def check(p,a,b,m,q,P: tuple, Q: tuple, signedMsg: tuple):
    E=EllipticCurve(GF(p),[a,b])
    P=E(P)
    Q=E(Q)
    
    l=0
    if (q>2**254) and (q<2**256):
        l=256
    elif (q>2**508) and (q<2**512):
        l=512
    
    
    sig=signedMsg[0]
    
    r=sig[:l//8]
    s=sig[l//8:]
    
    r=int.from_bytes(r,'big')
    s=int.from_bytes(s,'big')
    
    if not (r>0 and r<q and s>0 and r<q):
        return False
    
    h=Hash(signedMsg[1],l)
    
    alpha=int.from_bytes(h,'big')
    e=alpha%q
    if not e:
        e=1
    
    v=pow(e,-1,q)
    
    z1=(s*v)%q
    z2=(-r*v)%q
    
    C=z1*P+z2*Q
    
    R=int(C.xy()[0])%q
    
    
    return R==r








