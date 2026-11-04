"""Reproducible CLI/TShark comparison and bounded-memory smoke measurement.

Run from the repository root: .venv/bin/python -m tests.verify_synthetic
Only independently generated, header-only captures are used.
"""
from decimal import Decimal
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

from tests.synthetic import capture, ethernet, ipv4, ipv6, packet_record, pcap_header, samples, tcp, udp


def run_cli(source, destination):
    subprocess.run([sys.executable, "-m", "sentinelforge", "--input", str(source),
                    "--output", str(destination)], check=True)


def main():
    if not shutil.which("tshark"):
        raise SystemExit("TShark is required for independent verification")
    root = Path(tempfile.mkdtemp(prefix="sentinelforge-verification-"))
    source, destination = root / "synthetic.pcap", root / "sample.jsonl"
    packets = samples() + [
        ethernet(ipv4(udp(bytes(8), length=40), 17, 0x2000)),
        ethernet(ipv4(bytes(8), 17, 2)),
        ethernet(ipv6(bytes([17, 0]) + bytes(6) + udp(), 60), 0x86DD),
        ethernet(ipv6(struct.pack("!BBHI", 17, 0, 0, 42) + udp(), 44), 0x86DD),
    ]
    packets.extend([
        ethernet(ipv6(b"", 59), 0x86DD),
        ethernet(ipv6(bytes([60, 0]) + bytes(6) + bytes([17, 0]) + bytes(6) + udp(), 0), 0x86DD),
        ethernet(ipv6(struct.pack("!BBHI", 17, 0, 1, 43) + udp(bytes(8), length=40), 44), 0x86DD),
        ethernet(ipv6(struct.pack("!BBHI", 17, 0, 8, 43) + udp(), 44), 0x86DD),
        ethernet(ipv6(struct.pack("!BBHI", 60, 0, 1, 44) + bytes([17, 0]) + bytes(6) + udp(bytes(8), length=40), 44), 0x86DD),
        ethernet(ipv4(udp(length=8) + bytes(8), 17)),
        ethernet(ipv6(udp(length=8) + bytes(8)), 0x86DD),
        ethernet(ipv4(tcp(bytes(4)), 6, 0x2000)),
        ethernet(ipv6(bytes([17, 2]) + bytes(14) + udp(), 51), 0x86DD),
        ethernet(ipv6(tcp(options=bytes(8)), 6), 0x86DD),
        ethernet(ipv6(struct.pack("!BBHI", 60, 0, 8, 44) + bytes([17, 0]) + bytes(6) + udp(), 44), 0x86DD),
        ethernet(ipv6(struct.pack("!BBHI", 6, 0, 1, 45) + tcp(bytes(4)), 44), 0x86DD),
        ethernet(ipv6(bytes(8), 59), 0x86DD),
    ])
    comparisons = 0
    for endian in ("<", ">"):
        for nano in (False, True):
            source = root / f"synthetic-{'le' if endian == '<' else 'be'}-{'ns' if nano else 'us'}.pcap"
            destination = source.with_suffix(".jsonl")
            source.write_bytes(capture(*packets, endian=endian, nano=nano))
            run_cli(source, destination)
            records = [json.loads(line) for line in destination.read_text().splitlines()]
            compare_tshark(source, records)
            comparisons += len(records)
    print(f"TShark: {comparisons} packets across 4 byte-order/precision variants; all 8 compared fields and protocol numbers match")
    print("CLI sample: " + json.dumps(records[0], separators=(",", ":")))
    # Run each measurement in a fresh process; /usr/bin/time measures peak RSS.
    if Path("/usr/bin/time").exists():
        for count in (1000, 200000):
            large = root / f"memory-{count}.pcap"
            output = root / f"memory-{count}.jsonl"
            with large.open("wb") as stream:
                stream.write(pcap_header())
                frame = packet_record(ethernet(ipv4(tcp())))
                for _ in range(count):
                    stream.write(frame)
            timing = subprocess.run(["/usr/bin/time", "-f", "peak_rss_kib=%M elapsed_seconds=%e",
                                     sys.executable, "-m", "sentinelforge", "--input", str(large),
                                     "--output", str(output)], check=True, capture_output=True, text=True)
            with output.open() as stream:
                assert sum(1 for _ in stream) == count
            print(f"Memory: packets={count} input_bytes={large.stat().st_size} {timing.stderr.strip()}")
    else:
        print("Memory measurement skipped: /usr/bin/time unavailable")
    print(f"Synthetic verification artifacts: {root}")


def compare_tshark(source, records):
    fields = ["frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
              "tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport", "frame.len", "frame.cap_len"]
    command = ["tshark", "-n", "-r", str(source), "-o", "ip.defragment:FALSE",
               "-o", "ipv6.defragment:FALSE", "-T", "fields", "-E", "occurrence=f"]
    for field in fields:
        command.extend(["-e", field])
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    rows = result.stdout.splitlines()
    assert len(rows) == len(records)
    for record, line in zip(records, rows):
        values = dict(zip(fields, line.split("\t")))
        expected = {
            "packet_index": int(values["frame.number"]),
            "timestamp_ns": int(Decimal(values["frame.time_epoch"]) * 1_000_000_000),
            "src_ip": values["ip.src"] or values["ipv6.src"] or None,
            "dst_ip": values["ip.dst"] or values["ipv6.dst"] or None,
            "src_port": int(values["tcp.srcport"] or values["udp.srcport"]) if values["tcp.srcport"] or values["udp.srcport"] else None,
            "dst_port": int(values["tcp.dstport"] or values["udp.dstport"]) if values["tcp.dstport"] or values["udp.dstport"] else None,
            "packet_length": int(values["frame.len"]),
            "captured_length": int(values["frame.cap_len"]),
        }
        for name, value in expected.items():
            assert record[name] == value, (record["packet_index"], name, record[name], value)
    # Follow independently dissected Next Header fields, including repeated
    # Destination Options headers, rather than assuming ipv6.nxt is transport.
    next_fields = {0: "ipv6.hopopts.nxt", 43: "ipv6.routing.nxt", 44: "ipv6.fraghdr.nxt",
                   51: "ah.next_header", 60: "ipv6.dstopts.nxt"}
    protocol_fields = ["ip.proto", "ipv6.nxt", *next_fields.values()]
    command = ["tshark", "-n", "-r", str(source), "-o", "ip.defragment:FALSE",
               "-o", "ipv6.defragment:FALSE", "-T", "fields"]
    for field in protocol_fields:
        command.extend(["-e", field])
    protocols = subprocess.run(command, check=True, capture_output=True, text=True).stdout.splitlines()
    assert len(protocols) == len(records)
    for record, line in zip(records, protocols):
        fields = dict(zip(protocol_fields, line.split("\t")))
        number = int(fields["ip.proto"] or fields["ipv6.nxt"])
        following = {name: [int(n) for n in fields[name].split(",") if n]
                     for name in next_fields.values()}
        while number in next_fields and following[next_fields[number]]:
            number = following[next_fields[number]].pop(0)
        assert record["ip_protocol"] == number, (record["packet_index"], "ip_protocol", record["ip_protocol"], number)
        assert record["status"] == "complete", (record["packet_index"], record["status"])


if __name__ == "__main__":
    main()
