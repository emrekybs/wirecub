import struct, socket, os
pkts=[]
def eth(d,s,et,p): return bytes.fromhex(d)+bytes.fromhex(s)+struct.pack('!H',et)+p
def udp(sp,dp,p): return struct.pack('!HHHH',sp,dp,8+len(p),0)+p
A='001122334455'; B='66778899aabb'
t=1700300000

# A DNS-tunnel-like UDP payload split into three IPv4 fragments so the
# transport header and the payload land in different packets.
payload = udp(41234, 53, b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' +
              b''.join(bytes([len(l)])+l for l in [b'a'*50, b'exfil-tunnel', b'net']) + b'\x00\x00\x10\x00\x01' + b'X'*1400)

def ip4_frag(src,dst,proto,data,ident,offset,mf):
    flags_frag = (0x2000 if mf else 0) | (offset//8)
    h=struct.pack('!BBHHHBBH',0x45,0,20+len(data),ident,flags_frag,64,proto,0)+socket.inet_aton(src)+socket.inet_aton(dst)
    return h+data

chunks=[payload[i:i+616] for i in range(0,len(payload),616)]
off=0
for i,c in enumerate(chunks):
    mf = i < len(chunks)-1
    pkts.append((t+i*0.001, eth(A,B,0x0800, ip4_frag('192.168.9.5','192.168.9.1',17,c,4242,off,mf))))
    off+=len(c)

# IPv6 fragmented TCP: extension header 44 in front of the payload
def ip6_frag(src,dst,nh,data,ident,offset,mf):
    frag_hdr = struct.pack('!BBHI', nh, 0, (offset & 0xfff8) | (1 if mf else 0), ident)
    body = frag_hdr + data
    return struct.pack('!IHBB',6<<28,len(body),44,64)+socket.inet_pton(socket.AF_INET6,src)+socket.inet_pton(socket.AF_INET6,dst)+body

tcp_payload = struct.pack('!HHIIBBHHH',43210,80,1,0,5<<4,0x18,8192,0,0)+b'GET /fragmented-request-path HTTP/1.1\r\nHost: split.example\r\n\r\n'+b'P'*900
c6=[tcp_payload[i:i+520] for i in range(0,len(tcp_payload),520)]
o=0
for i,c in enumerate(c6):
    mf = i < len(c6)-1
    pkts.append((t+10+i*0.001, eth(A,B,0x86dd, ip6_frag('2001:db8::9','2001:db8::1',6,c,7777,o,mf))))
    o+=len(c)

with open('/tmp/frag.pcapng','wb') as f:
    f.write(struct.pack('<IIIHHq',0x0A0D0D0A,28,0x1A2B3C4D,1,0,-1)+struct.pack('<I',28))
    f.write(struct.pack('<III',0x00000001,20,1)+struct.pack('<I',65535)+struct.pack('<I',20))
    for ts,data in pkts:
        pad=(-len(data))%4; us=int(ts*1_000_000); blen=32+len(data)+pad
        f.write(struct.pack('<IIIIIII',0x00000006,blen,0,us>>32,us&0xffffffff,len(data),len(data)))
        f.write(data+b'\x00'*pad); f.write(struct.pack('<I',blen))
print('fragments:',len(pkts),'| udp payload:',len(payload),'| ipv6 payload:',len(tcp_payload))
