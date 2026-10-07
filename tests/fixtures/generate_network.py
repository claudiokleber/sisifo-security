"""Synthetic Ethernet/IPv4 UDP and TCP capture, no user traffic."""
import struct
from pathlib import Path


def checksum(data):
    total = sum(struct.unpack('!10H', data))
    total = (total & 65535) + (total >> 16)
    return (~total) & 65535


frames = []
for proto in (17, 6):
    transport = struct.pack('!HHHH', 12345, 9999, 8, 0) if proto == 17 else struct.pack('!HHIIBBHHH', 12345, 443, 1, 0, 80, 2, 8192, 0, 0)
    ip = struct.pack('!BBHHHBBH4s4s', 69, 0, 20 + len(transport), 1, 0, 64, proto, 0, bytes([192,0,2,1]), bytes([192,0,2,2]))
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    frames.append(bytes.fromhex('0200000000020200000000010800') + ip + transport)
root = Path(__file__).parent
pcap = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
for i, frame in enumerate(frames):
    pcap += struct.pack('<IIII', 1700000000 + i, 0, len(frame), len(frame)) + frame
(root / 'network-synthetic.pcap').write_bytes(pcap)

def block(kind, body):
    size = 12 + len(body)
    return struct.pack('<II', kind, size) + body + struct.pack('<I', size)

pcapng = block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
pcapng += block(1, struct.pack('<HHI', 1, 0, 65535))
for i, frame in enumerate(frames):
    ts = (1700000000 + i) * 1000000
    body = struct.pack('<IIIII', 0, ts >> 32, ts & 0xffffffff, len(frame), len(frame))
    pcapng += block(6, body + frame + b'\0' * (-len(frame) % 4))
(root / 'network-synthetic.pcapng').write_bytes(pcapng)
