import struct, socket, os
def ip4(s,d,proto,p):
    return struct.pack('!BBHHHBBH',0x45,0,20+len(p),1,0x4000,64,proto,0)+socket.inet_aton(s)+socket.inet_aton(d)+p
def ip6(s,d,nh,p):
    return struct.pack('!IHBB',6<<28,len(p),nh,64)+socket.inet_pton(socket.AF_INET6,s)+socket.inet_pton(socket.AF_INET6,d)+p
def tcp(sp,dp,p=b''): return struct.pack('!HHIIBBHHH',sp,dp,1,0,5<<4,0x18,8192,0,0)+p
def udp(sp,dp,p): return struct.pack('!HHHH',sp,dp,8+len(p),0)+p
def eth(d,s,et,p): return bytes.fromhex(d)+bytes.fromhex(s)+struct.pack('!H',et)+p
A='001122334455'; B='66778899aabb'
HTTP=b'GET /link-test HTTP/1.1\r\nHost: probe.local\r\n\r\n'

cases=[]
# 1 Ethernet plain
cases.append((1,'ethernet', eth(A,B,0x0800, ip4('10.1.0.1','10.1.0.2',6,tcp(1111,80,HTTP)))))
# 2 VLAN
cases.append((1,'vlan', bytes.fromhex(A)+bytes.fromhex(B)+struct.pack('!HHH',0x8100,300,0x0800)+ip4('10.2.0.1','10.2.0.2',6,tcp(1112,80,HTTP))))
# 3 QinQ
cases.append((1,'qinq', bytes.fromhex(A)+bytes.fromhex(B)+struct.pack('!HH',0x88a8,10)+struct.pack('!HH',0x8100,20)+struct.pack('!H',0x0800)+ip4('10.3.0.1','10.3.0.2',6,tcp(1113,80,HTTP))))
# 4 MPLS (bottom-of-stack bit set)
cases.append((1,'mpls', eth(A,B,0x8847, struct.pack('!I',(500<<12)|(1<<8)|64)+ip4('10.4.0.1','10.4.0.2',6,tcp(1114,80,HTTP)))))
# 5 GRE
inner=ip4('10.5.0.1','10.5.0.2',6,tcp(1115,80,HTTP))
cases.append((1,'gre', eth(A,B,0x0800, ip4('172.16.0.1','172.16.0.2',47, struct.pack('!HH',0,0x0800)+inner))))
# 6 VXLAN
vx_inner=eth(A,B,0x0800, ip4('10.6.0.1','10.6.0.2',6,tcp(1116,80,HTTP)))
cases.append((1,'vxlan', eth(A,B,0x0800, ip4('172.16.1.1','172.16.1.2',17, udp(40000,4789, b'\x08\x00\x00\x00'+b'\x00\x00\x64'+b'\x00'+vx_inner)))))
# 7 IP-in-IP
cases.append((1,'ipip', eth(A,B,0x0800, ip4('172.16.2.1','172.16.2.2',4, ip4('10.7.0.1','10.7.0.2',6,tcp(1117,80,HTTP))))))
# 8 6in4
cases.append((1,'6in4', eth(A,B,0x0800, ip4('172.16.3.1','172.16.3.2',41, ip6('2001:db8:8::1','2001:db8:8::2',6,tcp(1118,80,HTTP))))))
# 9 Linux cooked v1 (linktype 113)
cases.append((113,'sll', struct.pack('!HHH',0,1,6)+bytes.fromhex(B)+b'\x00\x00'+struct.pack('!H',0x0800)+ip4('10.9.0.1','10.9.0.2',6,tcp(1119,80,HTTP))))
# 10 Linux cooked v2 (linktype 276)
cases.append((276,'sll2', struct.pack('!H',0x0800)+b'\x00\x00'+struct.pack('!I',1)+struct.pack('!HH',1,6)+bytes.fromhex(B)+b'\x00\x00'+ip4('10.10.0.1','10.10.0.2',6,tcp(1120,80,HTTP))))
# 11 Raw IPv4 (linktype 101)
cases.append((101,'rawip', ip4('10.11.0.1','10.11.0.2',6,tcp(1121,80,HTTP))))
# 12 Null/loopback (linktype 0)
cases.append((0,'null', struct.pack('<I',2)+ip4('10.12.0.1','10.12.0.2',6,tcp(1122,80,HTTP))))
# 13 Raw IPv6 (linktype 229)
cases.append((229,'rawip6', ip6('2001:db8:13::1','2001:db8:13::2',6,tcp(1123,80,HTTP))))
# 14 802.11 + radiotap with LLC/SNAP
rt=struct.pack('<BBHI',0,0,8,0)
d11=struct.pack('<HH',0x0208,0)+bytes.fromhex(B)+bytes.fromhex(A)+bytes.fromhex(B)+struct.pack('<H',0)
llc=b'\xaa\xaa\x03\x00\x00\x00'+struct.pack('!H',0x0800)
cases.append((127,'dot11', rt+d11+llc+ip4('10.14.0.1','10.14.0.2',6,tcp(1124,80,HTTP))))
# 15 Geneve
gv_inner=eth(A,B,0x0800, ip4('10.15.0.1','10.15.0.2',6,tcp(1125,80,HTTP)))
cases.append((1,'geneve', eth(A,B,0x0800, ip4('172.16.5.1','172.16.5.2',17, udp(40001,6081, b'\x00\x00'+struct.pack('!H',0x6558)+b'\x00\x00\x0a\x00'+gv_inner)))))

# One pcapng per link type, since a section pins the interface link type
os.makedirs('/tmp/links', exist_ok=True)
for lt, name, pkt in cases:
    with open(f'/tmp/links/{name}.pcapng','wb') as f:
        f.write(struct.pack('<IIIHHq',0x0A0D0D0A,28,0x1A2B3C4D,1,0,-1)+struct.pack('<I',28))
        f.write(struct.pack('<III',0x00000001,20,lt)+struct.pack('<I',65535)+struct.pack('<I',20))
        for i in range(3):
            pad=(-len(pkt))%4; us=1700500000000000+i*1000; blen=32+len(pkt)+pad
            f.write(struct.pack('<IIIIIII',0x00000006,blen,0,us>>32,us&0xffffffff,len(pkt),len(pkt)))
            f.write(pkt+b'\x00'*pad); f.write(struct.pack('<I',blen))
print(f'{len(cases)} link-type fixtures written')
