import struct, socket, random, os, zlib
random.seed(11)
pkts=[]
def eth(dst,src,et,p): return bytes.fromhex(dst)+bytes.fromhex(src)+struct.pack('!H',et)+p
def ip4(s,d,proto,p,ttl=64):
    h=struct.pack('!BBHHHBBH',0x45,0,20+len(p),random.randint(1,65535),0x4000,ttl,proto,0)+socket.inet_aton(s)+socket.inet_aton(d)
    return h+p
def tcp(sp,dp,flags,p=b'',seq=1):
    return struct.pack('!HHIIBBHHH',sp,dp,seq,0,5<<4,flags,8192,0,0)+p
def udp(sp,dp,p): return struct.pack('!HHHH',sp,dp,8+len(p),0)+p
A='001122334455'; B='66778899aabb'; C='aabbccddeeff'
t=1700100000

# --- HTTP file download split across many packets (real PE) ---
pe = bytearray(b'MZ' + b'\x90\x00'*29 + b'\x00'*26)
pe += b'\x00'*(0x3c-len(pe)) + struct.pack('<I',0x80) + b'\x00'*(0x80-0x40)
# PE header
pe += b'PE\x00\x00' + struct.pack('<HHIIIHH',0x014c,2,0x5f000000,0,0,0xE0,0x0102)
opt = struct.pack('<H',0x010b) + b'\x00'*(0xE0-2)
pe += opt
for name,vsz,va,rsz,rp in ((b'.text',0x1000,0x1000,0x400,0x400),(b'UPX1',0x2000,0x2000,0x800,0x800)):
    pe += name.ljust(8,b'\x00') + struct.pack('<IIII',vsz,va,rsz,rp) + b'\x00'*16
pe += b'\x00'*(0x400-len(pe))
pe += b'UPX0UPX1UPX!' + bytes(random.getrandbits(8) for _ in range(0x400-12))
pe += b'powershell -enc ' + b'A'*80 + b'\x00'
pe += b'vssadmin delete shadows /all /quiet\x00'
pe += bytes(random.getrandbits(8) for _ in range(2000))
pe = bytes(pe)

req = b"GET /downloads/update.exe HTTP/1.1\r\nHost: cdn-update.biz\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
resp_head = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: image/png\r\nContent-Length: %d\r\n\r\n" % len(pe)
body = resp_head + pe
pkts.append((t, eth(A,B,0x0800, ip4('192.168.2.50','93.184.20.7',6, tcp(52000,80,0x02)))))
pkts.append((t+0.01, eth(B,A,0x0800, ip4('93.184.20.7','192.168.2.50',6, tcp(80,52000,0x12)))))
pkts.append((t+0.02, eth(A,B,0x0800, ip4('192.168.2.50','93.184.20.7',6, tcp(52000,80,0x18,req,seq=1)))))
seq=1
for i in range(0,len(body),1400):
    chunk=body[i:i+1400]
    pkts.append((t+0.05+i*0.0001, eth(B,A,0x0800, ip4('93.184.20.7','192.168.2.50',6, tcp(80,52000,0x18,chunk,seq=seq)))))
    seq+=len(chunk)

# --- SMB2 + NTLMv1 auth ---
def smb2(cmd, flags=0):
    return b'\x00'+b'\x00\x00\x60'+b'\xfeSMB'+b'\x00'*8+struct.pack('<H',cmd)+b'\x00\x00'+struct.pack('<I',flags)+b'\x00'*40
def ntlm3(user,domain,ws,nt_len=24):
    base=b'NTLMSSP\x00'+struct.pack('<I',3)
    off=64
    fields=b''
    parts=[]
    lm=b'\x00'*24; nt=b'\xaa'*nt_len
    du=domain.encode('utf-16-le'); uu=user.encode('utf-16-le'); wu=ws.encode('utf-16-le')
    cur=off
    def f(data):
        nonlocal cur
        r=struct.pack('<HHI',len(data),len(data),cur); cur+=len(data); return r
    hdr = base + f(lm) + f(nt) + f(du) + f(uu) + f(wu) + struct.pack('<HHI',0,0,cur) + struct.pack('<I',0)
    hdr = hdr.ljust(off,b'\x00')
    return b'\x00\x00\x00\x80' + hdr + lm+nt+du+uu+wu
for i,user in enumerate(['alice','bob','carol','dave','eve','frank','grace','heidi','ivan']):
    pkts.append((t+100+i, eth(A,B,0x0800, ip4('192.168.2.77','192.168.2.10',6, tcp(53000+i,445,0x18, ntlm3(user,'CORP','WS-ATTACK'))))))
for i in range(300):
    pkts.append((t+200+i*0.1, eth(A,B,0x0800, ip4('192.168.2.99','192.168.2.%d'%(10+i%3),6, tcp(54000,445,0x18, smb2(9))))))

# --- Kerberos TGS-REQ requesting RC4 (etype 23), properly DER encoded ---
def der(tag, content):
    if len(content) < 128: return bytes([tag, len(content)]) + content
    lb = len(content).to_bytes((len(content).bit_length()+7)//8, 'big')
    return bytes([tag, 0x80 | len(lb)]) + lb + content
def ctx(n, c): return der(0xA0 | n, c)
def i(v): return der(0x02, v.to_bytes(max(1,(v.bit_length()+7)//8), 'big'))
def gs(x): return der(0x1B, x.encode())
def sq(*items): return der(0x30, b''.join(items))

def kerb_tgs(service):
    body = sq(
        ctx(1, i(10)),
        ctx(2, sq(ctx(0, i(1)), ctx(1, sq(gs(service))))),
        ctx(3, gs('CORP.LOCAL')),
        ctx(8, sq(i(23), i(18), i(17))),
    )
    msg = der(0x6C, sq(ctx(1, i(5)), ctx(2, i(12)), ctx(4, body)))
    return struct.pack('!I', len(msg)) + msg

services = ['MSSQLSvc/db01.corp.local', 'HTTP/web01.corp.local',
            'CIFS/fs01.corp.local', 'MSSQLSvc/db02.corp.local']
for i_ in range(8):
    pkts.append((t+300+i_, eth(A,B,0x0800, ip4('192.168.2.77','192.168.2.5',6,
                tcp(55000+i_,88,0x18, kerb_tgs(services[i_ % len(services)]))))))

# --- Modbus write from external host ---
def modbus(fn,unit=1):
    pdu=struct.pack('!B',fn)+b'\x00\x01\x00\x01'
    return struct.pack('!HHHB',random.randint(1,999),0,len(pdu)+1,unit)+pdu
for i in range(12):
    pkts.append((t+400+i, eth(C,B,0x0800, ip4('198.18.7.9','192.168.2.200',6, tcp(56000,502,0x18, modbus(6))))))
for i in range(20):
    pkts.append((t+420+i, eth(A,B,0x0800, ip4('192.168.2.60','192.168.2.200',6, tcp(56100,502,0x18, modbus(3))))))

# --- MQTT anonymous + credentials in clear ---
def mqtt_connect(client,user=None,pw=False):
    payload=struct.pack('!H',4)+b'MQTT'+bytes([4])
    flags=0
    body=struct.pack('!H',len(client))+client.encode()
    if user: flags|=0x80; body+=struct.pack('!H',len(user))+user.encode()
    if pw: flags|=0x40; body+=struct.pack('!H',6)+b'secret'
    payload+=bytes([flags])+struct.pack('!H',60)+body
    return bytes([0x10, len(payload)])+payload
pkts.append((t+500, eth(A,B,0x0800, ip4('192.168.2.80','192.168.2.210',6, tcp(57000,1883,0x18, mqtt_connect('sensor-01'))))))
pkts.append((t+501, eth(A,B,0x0800, ip4('192.168.2.81','192.168.2.210',6, tcp(57001,1883,0x18, mqtt_connect('gw-02','admin',True))))))

# --- QUIC initial ---
for i in range(6):
    q=bytes([0xc0])+struct.pack('!I',0x00000001)+bytes([8])+os.urandom(8)+bytes([8])+os.urandom(8)+os.urandom(40)
    pkts.append((t+600+i, eth(A,B,0x0800, ip4('192.168.2.50','142.250.185.14',17, udp(58000+i,443,q)))))
q=bytes([0xc0])+struct.pack('!I',0xdeadbeef)+bytes([4])+os.urandom(4)+bytes([4])+os.urandom(4)+os.urandom(30)
pkts.append((t+610, eth(A,B,0x0800, ip4('192.168.2.50','45.32.9.9',17, udp(58100,443,q)))))

# --- SSDP ---
for i in range(4):
    ssdp=b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nSERVER: Linux/3.4 UPnP/1.0 IPCam/2.1\r\nNT: upnp:rootdevice\r\nUSN: uuid:cam-%d\r\n\r\n"%i
    pkts.append((t+700+i, eth(A,B,0x0800, ip4('192.168.2.%d'%(90+i),'239.255.255.250',17, udp(1900,1900,ssdp)))))

pkts.sort(key=lambda x:x[0])
with open('/tmp/scenario2.pcapng','wb') as f:
    f.write(struct.pack('<IIIHHq',0x0A0D0D0A,28,0x1A2B3C4D,1,0,-1)+struct.pack('<I',28))
    f.write(struct.pack('<III',0x00000001,20,1)+struct.pack('<I',65535)+struct.pack('<I',20))
    for ts,data in pkts:
        pad=(-len(data))%4; us=int(ts*1_000_000); blen=32+len(data)+pad
        f.write(struct.pack('<IIIIIII',0x00000006,blen,0,us>>32,us&0xffffffff,len(data),len(data)))
        f.write(data+b'\x00'*pad); f.write(struct.pack('<I',blen))
print('packets:',len(pkts),'size:',os.path.getsize('/tmp/scenario2.pcapng'),'pe size:',len(pe))
