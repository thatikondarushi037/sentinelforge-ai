"""Independent wire-format fixtures: standard library only, no dpkt."""
import ipaddress
import struct


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def tcp(payload=b"", options=b""):
    return struct.pack("!HHIIBBHHH", 49152, 443, 1, 0,
                       ((20 + len(options)) // 4) << 4, 2, 4096, 0, 0) + options + payload


def udp(payload=b"", length=None):
    return struct.pack("!HHHH", 5353, 9999, 8 + len(payload) if length is None else length, 0) + payload


def ipv4(body, protocol=6, fragment=0, options=b""):
    header = struct.pack("!BBHHHBBH4s4s", 0x40 | ((20 + len(options)) // 4), 0,
                         20 + len(options) + len(body), 123, fragment, 64, protocol, 0,
                         ipaddress.ip_address("192.0.2.10").packed,
                         ipaddress.ip_address("198.51.100.20").packed) + options
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + body


def ipv6(body, protocol=17):
    return struct.pack("!IHBB16s16s", 6 << 28, len(body), protocol, 64,
                       ipaddress.ip_address("2001:db8::1").packed,
                       ipaddress.ip_address("2001:db8::2").packed) + body


def ethernet(body, kind=0x0800, tags=0):
    base = bytes.fromhex("020000000002020000000001")
    return base + (b"\x81\x00\x00\x01" * tags) + struct.pack("!H", kind) + body


def pcap_header(endian="<", nano=False, linktype=1, snaplen=1048576):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    return struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, snaplen, linktype)


def packet_record(data, endian="<", seconds=1735689600, fraction=123456, original=None):
    return struct.pack(endian + "IIII", seconds, fraction, len(data),
                       len(data) if original is None else original) + data


def capture(*packets, endian="<", nano=False):
    return pcap_header(endian, nano) + b"".join(packet_record(p, endian) for p in packets)


def samples():
    return [ethernet(ipv4(tcp())), ethernet(ipv4(udp(), 17)),
            ethernet(ipv6(udp()), 0x86DD), ethernet(ipv6(tcp(), 6), 0x86DD),
            ethernet(ipv4(b"\x08\0\0\0\0\0\0\0", 1)),
            ethernet(ipv6(b"\x80\0\0\0\0\0\0\0", 58), 0x86DD),
            ethernet(ipv4(tcp()), tags=1)]
