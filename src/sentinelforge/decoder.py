"""Bounded header traversal. Payloads are never decoded or exported."""
import ipaddress
import struct
import dpkt
from .records import Record

MAX_VLAN_TAGS = 4
MAX_IPV6_EXTENSIONS = 8


class DecodeFailure(Exception):
    def __init__(self, status):
        self.status = status


def decode(packet, capture_id):
    data = packet.data
    record = Record(capture_id, packet.index, packet.timestamp_ns,
                    packet.original_length, len(data))
    capture_short = len(data) < packet.original_length
    if capture_short:
        record.status = "truncated"

    def need(offset, size, limit=None):
        if limit is not None and offset + size > limit:
            raise DecodeFailure("malformed")
        if offset + size > len(data):
            raise DecodeFailure("truncated" if capture_short else "malformed")

    def protocol(number):
        record.ip_protocol = number
        record.protocol = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}.get(number, str(number))

    try:
        need(0, 14)
        kind = struct.unpack_from("!H", data, 12)[0]
        offset = 14
        tags = 0
        while kind in (0x8100, 0x88A8):
            if tags >= MAX_VLAN_TAGS:
                raise DecodeFailure("unsupported")
            need(offset, 4)
            kind = struct.unpack_from("!H", data, offset + 2)[0]
            offset += 4
            tags += 1
        more_fragments = False
        noninitial = False
        if kind == 0x0800:
            version = 4
            need(offset, 20)
            ip = dpkt.ip.IP()
            dpkt.Packet.unpack(ip, data[offset:offset + 20])
            size = (data[offset] & 15) * 4
            if ip.v != 4 or size < 20 or ip.len < size:
                raise DecodeFailure("malformed")
            limit = offset + ip.len
            if limit > packet.original_length:
                raise DecodeFailure("malformed")
            need(offset, size, limit)
            record.src_ip = str(ipaddress.IPv4Address(ip.src))
            record.dst_ip = str(ipaddress.IPv4Address(ip.dst))
            flags_offset = struct.unpack_from("!H", data, offset + 6)[0]
            noninitial = bool(flags_offset & 0x1FFF)
            more_fragments = bool(flags_offset & 0x2000)
            record.fragmented = noninitial or more_fragments
            protocol(ip.p)
            offset += size
            if more_fragments and (limit == offset or (limit - offset) % 8):
                raise DecodeFailure("malformed")
        elif kind == 0x86DD:
            version = 6
            need(offset, 40)
            # Bypass IP6.unpack's automatic extension/payload decoding. Only
            # fixed fields are needed; traversal below enforces our limits.
            ip = dpkt.ip6.IP6()
            dpkt.Packet.unpack(ip, data[offset:offset + 40])
            if ip.v != 6:
                raise DecodeFailure("malformed")
            record.src_ip = str(ipaddress.IPv6Address(ip.src))
            record.dst_ip = str(ipaddress.IPv6Address(ip.dst))
            if ip.plen == 0 and ip.nxt != 59:
                raise DecodeFailure("unsupported")
            limit = offset + 40 + ip.plen
            if limit > packet.original_length:
                raise DecodeFailure("malformed")
            number = ip.nxt
            offset += 40
            extensions = 0
            fragment_seen = False
            while number in (0, 43, 44, 51, 60):
                if number == 0 and extensions:
                    raise DecodeFailure("malformed")
                if extensions >= MAX_IPV6_EXTENSIONS:
                    raise DecodeFailure("unsupported")
                extensions += 1
                need(offset, 2, limit)
                following = data[offset]
                if number == 44:
                    if fragment_seen:
                        raise DecodeFailure("malformed")
                    fragment_seen = True
                    size = 8
                    need(offset, size, limit)
                    bits = struct.unpack_from("!H", data, offset + 2)[0]
                    noninitial = bool(bits & 0xFFF8)
                    more_fragments = bool(bits & 1)
                    record.fragmented = True
                    fragment_length = limit - offset - size
                    if more_fragments and (fragment_length == 0 or fragment_length % 8):
                        raise DecodeFailure("malformed")
                elif number == 51:
                    size = (data[offset + 1] + 2) * 4
                    if size < 12:
                        raise DecodeFailure("malformed")
                else:
                    size = (data[offset + 1] + 1) * 8
                need(offset, size, limit)
                offset += size
                number = following
                if noninitial:
                    break
            protocol(number)
            # An unfinished/unknown chain may still hide a Fragment header.
            if record.fragmented is None and number in (6, 17, 1, 58, 59):
                record.fragmented = False
        else:
            raise DecodeFailure("non_ip")

        if limit > len(data):
            record.status = "truncated"
        if noninitial:
            return record
        if record.ip_protocol == 6:
            need(offset, 20, limit)
            size = (data[offset + 12] >> 4) * 4
            if size < 20:
                raise DecodeFailure("malformed")
            need(offset, size, limit)
            tcp = dpkt.tcp.TCP(data[offset:offset + size])
            record.src_port, record.dst_port = tcp.sport, tcp.dport
        elif record.ip_protocol == 17:
            need(offset, 8, limit)
            udp = dpkt.udp.UDP(data[offset:offset + 8])
            # Ignore trailing IP padding beyond the UDP datagram. Subsequent
            # fragments can supply the remainder of a longer UDP datagram.
            if udp.ulen < 8 or (not more_fragments and udp.ulen > limit - offset):
                raise DecodeFailure("malformed")
            record.src_port, record.dst_port = udp.sport, udp.dport
        elif record.ip_protocol in (1, 58):
            need(offset, 8, limit)
        elif version != 6 or record.ip_protocol != 59:
            raise DecodeFailure("unsupported")
    except DecodeFailure as exc:
        record.status = exc.status
    except (dpkt.UnpackError, ValueError, struct.error):
        record.status = "malformed"
    return record
