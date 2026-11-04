import json
import struct
import unittest
from sentinelforge.decoder import decode
from sentinelforge.pcap_reader import Packet
from tests.synthetic import ethernet, ipv4, ipv6, samples, tcp, udp


def parse(data, original=None):
    return decode(Packet(1, 123456789, len(data) if original is None else original, data), "synthetic")


class DecoderTests(unittest.TestCase):
    def test_common_protocols(self):
        for data, protocol in zip(samples(), ["TCP", "UDP", "UDP", "TCP", "ICMP", "ICMPv6", "TCP"]):
            with self.subTest(protocol=protocol):
                r = parse(data)
                self.assertEqual(r.status, "complete")
                self.assertEqual(r.protocol, protocol)
                self.assertEqual(r.src_port, 49152 if protocol == "TCP" else 5353 if protocol == "UDP" else None)

    def test_addresses_lengths_identity(self):
        data = samples()[0]
        r = parse(data)
        self.assertEqual((r.src_ip, r.dst_ip), ("192.0.2.10", "198.51.100.20"))
        self.assertEqual((r.capture_id, r.packet_index, r.timestamp_ns), ("synthetic", 1, 123456789))
        self.assertEqual((r.packet_length, r.captured_length), (54, 54))
        self.assertEqual(parse(samples()[2]).src_ip, "2001:db8::1")

    def test_non_ip(self):
        r = parse(ethernet(bytes(28), 0x0806))
        self.assertEqual(r.status, "non_ip")
        self.assertIsNone(r.src_ip)
        self.assertIsNone(r.protocol)

    def test_unknown_protocol(self):
        r = parse(ethernet(ipv4(bytes(8), 253)))
        self.assertEqual((r.status, r.protocol, r.src_port), ("unsupported", "253", None))

    def test_all_prefixes_do_not_crash_or_fabricate_ports(self):
        for data in samples():
            for length in range(len(data)):
                r = parse(data[:length], len(data))
                self.assertEqual(r.status, "truncated")
                self.assertIsNone(r.src_port)

    def test_truncated_payload_keeps_complete_header_ports(self):
        data = ethernet(ipv4(tcp(b"synthetic-body")))
        r = parse(data[:-3], len(data))
        self.assertEqual((r.status, r.src_port), ("truncated", 49152))

    def test_tcp_options_must_be_complete(self):
        data = ethernet(ipv4(tcp(options=bytes(4))))
        r = parse(data[:-2], len(data))
        self.assertEqual((r.status, r.src_port), ("truncated", None))

    def test_ipv4_options(self):
        self.assertEqual(parse(ethernet(ipv4(tcp(), options=bytes(4)))).src_port, 49152)

    def test_ipv4_fragments(self):
        first = parse(ethernet(ipv4(udp(bytes(8), length=40), 17, 0x2000)))
        later = parse(ethernet(ipv4(tcp(), 6, 1)))
        self.assertEqual((first.status, first.src_port, first.fragmented), ("complete", 5353, True))
        self.assertEqual((later.status, later.src_port, later.fragmented), ("complete", None, True))

    def test_ipv6_fragments(self):
        for bits, expected in [(0, 5353), (1, 5353), (8, None)]:
            fragment = struct.pack("!BBHI", 17, 0, bits, 42)
            body = udp(bytes(8), length=40 if bits == 1 else 16)
            r = parse(ethernet(ipv6(fragment + body, 44), 0x86DD))
            self.assertEqual((r.status, r.src_port, r.fragmented), ("complete", expected, True))

    def test_ipv6_extension_chain_and_limits(self):
        for count, status in [(1, "complete"), (8, "complete"), (9, "unsupported")]:
            body = udp()
            number = 17
            for _ in range(count):
                body = bytes([number, 0]) + bytes(6) + body
                number = 60
            r = parse(ethernet(ipv6(body, number), 0x86DD))
            self.assertEqual(r.status, status)

    def test_ipv6_noninitial_does_not_traverse_fragment_data(self):
        body = struct.pack("!BBHI", 60, 0, 8, 42) + bytes(8)
        r = parse(ethernet(ipv6(body, 44), 0x86DD))
        self.assertEqual((r.status, r.ip_protocol, r.src_port), ("complete", 60, None))

    def test_ipv6_ah_and_esp(self):
        ah = bytes([17, 1]) + bytes(10) + udp()
        self.assertEqual(parse(ethernet(ipv6(ah, 51), 0x86DD)).src_port, 5353)
        self.assertEqual(parse(ethernet(ipv6(bytes(16), 50), 0x86DD)).status, "unsupported")

    def test_vlan_limit(self):
        self.assertEqual(parse(ethernet(ipv4(tcp()), tags=4)).status, "complete")
        self.assertEqual(parse(ethernet(ipv4(tcp()), tags=5)).status, "unsupported")

    def test_malformed_headers(self):
        cases = [ethernet(ipv4(tcp())[:10]), ethernet(ipv4(tcp()[:10])),
                 ethernet(ipv4(udp(length=7), 17)), ethernet(ipv4(udp(length=99), 17)),
                 ethernet(ipv4(tcp()[:12] + b"\x40" + tcp()[13:]))]
        for data in cases:
            with self.subTest(data_length=len(data)):
                r = parse(data)
                self.assertEqual(r.status, "malformed")
                self.assertIsNone(r.src_port)

    def test_payload_never_exported(self):
        marker = b"SYNTHETIC_SECRET_DO_NOT_EXPORT"
        encoded = json.dumps(parse(ethernet(ipv4(tcp(marker)))).to_dict())
        self.assertNotIn(marker.decode(), encoded)
        self.assertNotIn("payload", encoded)
