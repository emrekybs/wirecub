import struct, os
pkts=[]
def radiotap(): return struct.pack('<BBHI',0,0,8,0)
def d11(subtype, dst, src, bssid, body=b'', ftype=0):
    fc = (subtype << 4) | (ftype << 2)
    return struct.pack('<HH', fc, 0) + bytes.fromhex(dst)+bytes.fromhex(src)+bytes.fromhex(bssid)+struct.pack('<H',0) + body
def beacon(ssid, bssid, rsn=True):
    fixed = b'\x00'*8 + struct.pack('<H',100) + struct.pack('<H', 0x0011 if rsn else 0x0001)
    ies = bytes([0, len(ssid)]) + ssid.encode()
    ies += bytes([1,4]) + b'\x82\x84\x8b\x96'
    if rsn: ies += bytes([48,20]) + b'\x01\x00'+b'\x00\x0f\xac\x04'*2+b'\x01\x00'+b'\x00\x0f\xac\x02'+b'\x00\x00'
    return d11(8, 'ffffffffffff', bssid, bssid, fixed+ies)
def deauth(dst, src, bssid, reason=7):
    return d11(12, dst, src, bssid, struct.pack('<H', reason))
def eapol(msg):
    key_info = {1:0x008a, 2:0x010a, 3:0x13ca, 4:0x030a}[msg]
    body = b'\x01\x03' + struct.pack('!H',117) + b'\x02' + struct.pack('!H',key_info) + b'\x00'*100
    llc = b'\xaa\xaa\x03\x00\x00\x00' + struct.pack('!H',0x888e)
    return d11(0, 'aabbccddee01', 'aabbccddee02', 'aabbccddee02', b'', ftype=2) + llc + body

t=1700600000
# Legitimate AP, then a second radio serving the same name with weaker security
for i in range(30): pkts.append((t+i*0.1, radiotap()+beacon('CORP-WIFI','aabbccddee02')))
for i in range(25): pkts.append((t+3+i*0.1, radiotap()+beacon('CORP-WIFI','001122334499', rsn=False)))
for i in range(12): pkts.append((t+6+i*0.1, radiotap()+beacon('GUEST','aabbccddee03')))
# Deauthentication flood
for i in range(60): pkts.append((t+10+i*0.05, radiotap()+deauth('aabbccddee01','aabbccddee02','aabbccddee02')))
for i in range(20): pkts.append((t+14+i*0.05, radiotap()+deauth('ffffffffffff','aabbccddee02','aabbccddee02', reason=1)))
# Four-way handshake captured right afterwards
for m in (1,2,3,4): pkts.append((t+16+m*0.02, radiotap()+eapol(m)))

pkts.sort(key=lambda x:x[0])
with open('/tmp/wifi.pcapng','wb') as f:
    f.write(struct.pack('<IIIHHq',0x0A0D0D0A,28,0x1A2B3C4D,1,0,-1)+struct.pack('<I',28))
    f.write(struct.pack('<III',0x00000001,20,127)+struct.pack('<I',65535)+struct.pack('<I',20))
    for ts,data in pkts:
        pad=(-len(data))%4; us=int(ts*1_000_000); blen=32+len(data)+pad
        f.write(struct.pack('<IIIIIII',0x00000006,blen,0,us>>32,us&0xffffffff,len(data),len(data)))
        f.write(data+b'\x00'*pad); f.write(struct.pack('<I',blen))
print('wifi packets:',len(pkts))
