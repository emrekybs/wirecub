import struct, socket, random, os, sys
random.seed(99)
target_mb = int(sys.argv[1]) if len(sys.argv)>1 else 200
def eth(d,s,et,p): return bytes.fromhex(d)+bytes.fromhex(s)+struct.pack('!H',et)+p
def ip4(s,d,proto,p):
    return struct.pack('!BBHHHBBH',0x45,0,20+len(p),random.randint(1,65535),0x4000,64,proto,0)+socket.inet_aton(s)+socket.inet_aton(d)+p
def tcp(sp,dp,flags,p=b''): return struct.pack('!HHIIBBHHH',sp,dp,random.randint(1,2**31),0,5<<4,flags,8192,0,0)+p
def udp(sp,dp,p): return struct.pack('!HHHH',sp,dp,8+len(p),0)+p
MACS=['%012x'%random.getrandbits(48) for _ in range(60)]
INT=['10.%d.%d.%d'%(random.randint(0,40),random.randint(0,255),random.randint(1,254)) for _ in range(900)]
EXT=['%d.%d.%d.%d'%(random.randint(11,220),random.randint(0,255),random.randint(0,255),random.randint(1,254)) for _ in range(600)]
t=1700400000.0
written=0
n=0
with open('/tmp/big.pcapng','wb') as f:
    f.write(struct.pack('<IIIHHq',0x0A0D0D0A,28,0x1A2B3C4D,1,0,-1)+struct.pack('<I',28))
    f.write(struct.pack('<III',0x00000001,20,1)+struct.pack('<I',65535)+struct.pack('<I',20))
    target = target_mb*1024*1024
    payload_pool=[bytes(random.getrandbits(8) for _ in range(s)) for s in (60,200,700,1400)]
    while written < target:
        for _ in range(2000):
            r=random.random()
            src=random.choice(INT)
            if r<0.55:
                dst=random.choice(EXT); pl=random.choice(payload_pool)
                pkt=eth(random.choice(MACS),random.choice(MACS),0x0800, ip4(src,dst,6, tcp(random.randint(1024,65535),random.choice([80,443,8443]),0x18,pl)))
            elif r<0.75:
                dst=random.choice(INT); pl=random.choice(payload_pool)
                pkt=eth(random.choice(MACS),random.choice(MACS),0x0800, ip4(src,dst,6, tcp(random.randint(1024,65535),random.choice([445,3389,22]),0x18,pl)))
            elif r<0.9:
                q=b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+b''.join(bytes([len(l)])+l for l in [b'host%d'%random.randint(1,9999), b'example', b'com'])+b'\x00\x00\x01\x00\x01'
                pkt=eth(random.choice(MACS),random.choice(MACS),0x0800, ip4(src,'10.0.0.53',17, udp(random.randint(1024,65535),53,q)))
            else:
                pkt=eth(random.choice(MACS),random.choice(MACS),0x0800, ip4(src,random.choice(EXT),1, struct.pack('!BBHHH',8,0,0,1,n & 0xffff)+b'\x00'*56))
            n+=1
            t+=0.0004
            pad=(-len(pkt))%4; us=int(t*1_000_000); blen=32+len(pkt)+pad
            f.write(struct.pack('<IIIIIII',0x00000006,blen,0,us>>32,us&0xffffffff,len(pkt),len(pkt)))
            f.write(pkt+b'\x00'*pad); f.write(struct.pack('<I',blen))
            written+=blen
        if written>=target: break
print(f'{os.path.getsize("/tmp/big.pcapng")/1048576:.0f} MB, {n:,} packets')
