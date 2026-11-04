import io
import struct
import unittest
from sentinelforge.pcap_reader import CaptureError, MAX_CAPTURED_LENGTH, read_packets
from tests.synthetic import capture, ethernet, ipv4, tcp, packet_record, pcap_header


class ReaderTests(unittest.TestCase):
    def test_byte_orders_and_precisions(self):
        for endian in ("<", ">"):
            for nano in (False, True):
                with self.subTest(endian=endian, nano=nano):
                    result = list(read_packets(io.BytesIO(capture(b"abc", endian=endian, nano=nano))))
                    self.assertEqual(result[0].timestamp_ns, 1735689600000000000 + 123456 * (1 if nano else 1000))
                    self.assertEqual(result[0].index, 1)

    def test_empty_capture(self):
        self.assertEqual(list(read_packets(io.BytesIO(pcap_header()))), [])

    def test_bad_headers(self):
        for data, code in [(b"", "incomplete_global_header"),
                           (b"\x0a\x0d\x0d\x0a", "unsupported_pcapng"),
                           (b"x" * 24, "invalid_pcap_magic"),
                           (pcap_header(linktype=113), "unsupported_link_type"),
                           (pcap_header(snaplen=0), "invalid_snaplen"),
                           (pcap_header() + b"x", "incomplete_packet_header"),
                           (pcap_header() + packet_record(b"abc")[:-1], "incomplete_packet_body")]:
            with self.subTest(code=code), self.assertRaisesRegex(CaptureError, code):
                list(read_packets(io.BytesIO(data)))

    def test_lengths_checked_before_body_read(self):
        class Guard(io.BytesIO):
            def read(self, size=-1):
                if size > 24:
                    raise AssertionError("allocated before validation")
                return super().read(size)
        for captured, original, snaplen, code in [
            (MAX_CAPTURED_LENGTH + 1, MAX_CAPTURED_LENGTH + 1, 2**32-1, "captured_record_too_large"),
            (20, 19, 100, "invalid_packet_lengths"),
            (20, 20, 19, "invalid_packet_lengths")]:
            data = pcap_header(snaplen=snaplen) + struct.pack("<IIII", 0, 0, captured, original)
            with self.subTest(code=code), self.assertRaisesRegex(CaptureError, code):
                list(read_packets(Guard(data)))

    def test_exact_limit(self):
        result = next(read_packets(io.BytesIO(capture(bytes(MAX_CAPTURED_LENGTH)))))
        self.assertEqual(len(result.data), MAX_CAPTURED_LENGTH)

    def test_invalid_fraction(self):
        data = pcap_header() + packet_record(b"", fraction=1000000)
        with self.assertRaisesRegex(CaptureError, "invalid_timestamp_fraction"):
            list(read_packets(io.BytesIO(data)))

    def test_original_length_retained(self):
        data = pcap_header() + packet_record(b"abc", original=100)
        self.assertEqual(next(read_packets(io.BytesIO(data))).original_length, 100)

    def test_indices_and_nonmonotonic_timestamps(self):
        data = pcap_header() + packet_record(b"", seconds=3) + packet_record(b"", seconds=1)
        result = list(read_packets(io.BytesIO(data)))
        self.assertEqual([p.index for p in result], [1, 2])
        self.assertGreater(result[0].timestamp_ns, result[1].timestamp_ns)
