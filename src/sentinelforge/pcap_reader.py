"""Strict classic-PCAP framing; no allocation follows an unchecked length."""
import struct
from dataclasses import dataclass

MAX_CAPTURED_LENGTH = 1024 * 1024
MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1000),
    b"\xa1\xb2\xc3\xd4": (">", 1000),
    b"\x4d\x3c\xb2\xa1": ("<", 1),
    b"\xa1\xb2\x3c\x4d": (">", 1),
}


class CaptureError(Exception):
    """Fixed, non-sensitive error codes only."""


@dataclass(slots=True)
class Packet:
    index: int
    timestamp_ns: int
    original_length: int
    data: bytes


def read_packets(stream):
    header = stream.read(24)
    if header[:4] == b"\x0a\x0d\x0d\x0a":
        raise CaptureError("unsupported_pcapng")
    if len(header) != 24:
        raise CaptureError("incomplete_global_header")
    if header[:4] not in MAGICS:
        raise CaptureError("invalid_pcap_magic")
    endian, multiplier = MAGICS[header[:4]]
    major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHiIII", header[4:])
    if (major, minor) != (2, 4):
        raise CaptureError("unsupported_pcap_version")
    if linktype != 1:
        raise CaptureError("unsupported_link_type")
    if snaplen == 0:
        raise CaptureError("invalid_snaplen")
    index = 0
    while True:
        raw = stream.read(16)
        if not raw:
            return
        if len(raw) != 16:
            raise CaptureError("incomplete_packet_header")
        seconds, fraction, captured, original = struct.unpack(endian + "IIII", raw)
        if fraction >= 1_000_000_000 // multiplier:
            raise CaptureError("invalid_timestamp_fraction")
        if captured > MAX_CAPTURED_LENGTH:
            raise CaptureError("captured_record_too_large")
        if captured > snaplen or captured > original:
            raise CaptureError("invalid_packet_lengths")
        data = stream.read(captured)
        if len(data) != captured:
            raise CaptureError("incomplete_packet_body")
        index += 1
        yield Packet(index, seconds * 1_000_000_000 + fraction * multiplier, original, data)
