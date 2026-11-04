"""Independent regression cases for the Milestone 1 quality review."""
import contextlib
import io
import json
import multiprocessing
from pathlib import Path
import random
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch

from sentinelforge.cli import main
from sentinelforge.records import Record
from sentinelforge.writer import write_atomic
from tests.synthetic import capture, ethernet, ipv4, ipv6, packet_record, pcap_header, tcp, udp
from tests.test_decoder import parse


def writer_process(destination, identity, ready, release, results):
    """Every writer finishes serializing before the parent releases publication."""
    def records():
        for index in range(1, 65):
            yield Record(identity, index, 0, 0, 0)
        ready.put(identity)
        release.wait(timeout=20)
    try:
        write_atomic(destination, records())
        results.put((identity, "published"))
    except FileExistsError:
        results.put((identity, "exists"))
    except Exception as exc:
        results.put((identity, type(exc).__name__))


class PublicationReviewTests(unittest.TestCase):
    def test_eight_concurrent_processes_publish_exactly_one_complete_file(self):
        context = multiprocessing.get_context("spawn")
        with tempfile.TemporaryDirectory() as root:
            destination = Path(root) / "race.jsonl"
            ready, results = context.Queue(), context.Queue()
            release = context.Barrier(9)
            identities = [f"writer-{i}" for i in range(8)]
            expected = {
                identity: "".join(json.dumps(Record(identity, i, 0, 0, 0).to_dict(),
                                            separators=(",", ":")) + "\n" for i in range(1, 65)).encode()
                for identity in identities
            }
            processes = [context.Process(target=writer_process,
                                         args=(destination, identity, ready, release, results))
                         for identity in identities]
            stop = threading.Event()
            bad_reads = []
            observations = []
            published_seen = threading.Event()

            def observe():
                while not stop.is_set():
                    try:
                        data = destination.read_bytes()
                    except FileNotFoundError:
                        pass
                    else:
                        observations.append(len(data))
                        if data not in expected.values():
                            bad_reads.append(len(data))
                        published_seen.set()
                    stop.wait(0.001)

            observer = threading.Thread(target=observe)
            try:
                for process in processes:
                    process.start()
                self.assertEqual({ready.get(timeout=20) for _ in processes}, set(identities))
                self.assertFalse(destination.exists())
                observer.start()
                release.wait(timeout=20)
                outcomes = [results.get(timeout=20) for _ in processes]
                for process in processes:
                    process.join(timeout=10)
                    self.assertEqual(process.exitcode, 0)
                winners = [identity for identity, outcome in outcomes if outcome == "published"]
                self.assertEqual(len(winners), 1)
                self.assertEqual(sum(outcome == "exists" for _, outcome in outcomes), 7)
                self.assertEqual(destination.read_bytes(), expected[winners[0]])
                self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
                self.assertEqual(list(Path(root).glob(".sentinelforge-*.tmp")), [])
                self.assertTrue(published_seen.wait(timeout=5))
            finally:
                stop.set()
                if observer.ident is not None:
                    observer.join(timeout=5)
                for process in processes:
                    if process.is_alive():
                        process.terminate()
                    if process.pid is not None:
                        process.join(timeout=5)
                for queue in (ready, results):
                    queue.close()
                    queue.join_thread()
            self.assertTrue(observations, "observer must read the published file")
            self.assertEqual(bad_reads, [])

    def test_rename_failure_leaves_no_destination_or_temporary_output(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "output.jsonl"
            with patch("sentinelforge.writer.rename_noreplace", side_effect=OSError("private")):
                with self.assertRaises(OSError):
                    write_atomic(output, [Record("synthetic", 1, 0, 0, 0)])
            self.assertEqual(list(Path(root).iterdir()), [])


class DecoderReviewTests(unittest.TestCase):
    def test_ipv4_does_not_treat_ipv6_no_next_as_supported(self):
        r = parse(ethernet(ipv4(b"", 59)))
        self.assertEqual((r.status, r.ip_protocol, r.src_port), ("unsupported", 59, None))

    def test_empty_ipv6_no_next_header(self):
        r = parse(ethernet(ipv6(b"", 59), 0x86DD))
        self.assertEqual((r.status, r.ip_protocol, r.fragmented), ("complete", 59, False))
        self.assertIsNone(r.src_port)

    def test_incomplete_or_unsupported_ipv6_chain_has_unknown_fragmentation(self):
        data = ethernet(ipv6(bytes([44, 0]) + bytes(6) + struct.pack("!BBHI", 17, 0, 0, 42) + udp(), 60), 0x86DD)
        for end in range(54, 70):
            with self.subTest(end=end):
                r = parse(data[:end], len(data))
                self.assertEqual(r.status, "truncated")
                self.assertIsNone(r.fragmented)
                self.assertIsNone(r.src_port)
        r = parse(ethernet(ipv6(bytes(8), 253), 0x86DD))
        self.assertEqual(r.status, "unsupported")
        self.assertIsNone(r.fragmented)

    def test_hop_by_hop_must_be_first(self):
        for first in (0, 43, 60):
            body = bytes([0, 0]) + bytes(6) + bytes([17, 0]) + bytes(6) + udp()
            r = parse(ethernet(ipv6(body, first), 0x86DD))
            self.assertEqual(r.status, "malformed")
            self.assertIsNone(r.src_port)

    def test_nonfinal_fragments_must_be_aligned(self):
        for body in (b"", udp(b"x", length=40)):
            for data in [ethernet(ipv4(body, 17, 0x2000)),
                         ethernet(ipv6(struct.pack("!BBHI", 17, 0, 1, 42) + body, 44), 0x86DD)]:
                with self.subTest(size=len(data)):
                    r = parse(data)
                    self.assertEqual(r.status, "malformed")
                    self.assertIsNone(r.src_port)

    def test_udp_may_have_trailing_ip_padding(self):
        for data in [ethernet(ipv4(udp(length=8) + bytes(8), 17)),
                     ethernet(ipv6(udp(length=8) + bytes(8)), 0x86DD)]:
            self.assertEqual((parse(data).status, parse(data).src_port), ("complete", 5353))

    def test_extension_lengths_cannot_escape_declared_ip_length_into_padding(self):
        # There are enough Ethernet bytes, but the IPv6 payload itself ends early.
        body = bytes([17, 1]) + bytes(6)
        data = ethernet(ipv6(body, 60) + bytes(16), 0x86DD)
        r = parse(data)
        self.assertEqual(r.status, "malformed")
        self.assertIsNone(r.src_port)

    def test_duplicate_fragment_header_is_malformed(self):
        body = struct.pack("!BBHI", 44, 0, 0, 42) + struct.pack("!BBHI", 17, 0, 0, 42) + udp()
        r = parse(ethernet(ipv6(body, 44), 0x86DD))
        self.assertEqual((r.status, r.fragmented, r.src_port), ("malformed", True, None))

    def test_partial_ipv6_tcp_options_do_not_supply_ports(self):
        data = ethernet(ipv6(tcp(options=bytes(8)), 6), 0x86DD)
        for end in range(54, len(data)):
            r = parse(data[:end], len(data))
            self.assertEqual(r.status, "truncated")
            self.assertIsNone(r.src_port)

    def test_noninitial_ipv6_fragment_never_decodes_apparent_udp_header(self):
        body = struct.pack("!BBHI", 17, 0, 8, 42) + udp()
        r = parse(ethernet(ipv6(body, 44), 0x86DD))
        self.assertEqual((r.status, r.fragmented, r.src_port, r.dst_port), ("complete", True, None, None))

    def test_deterministic_malformed_mutations_remain_safe(self):
        rng = random.Random(20261104)
        bases = [ethernet(ipv4(tcp())), ethernet(ipv4(udp(), 17)),
                 ethernet(ipv6(tcp(), 6), 0x86DD),
                 ethernet(ipv6(bytes([17, 0]) + bytes(6) + udp(), 60), 0x86DD)]
        statuses = {"complete", "truncated", "malformed", "unsupported", "non_ip"}
        for index in range(2000):
            data = bytearray(bases[index % len(bases)])
            for _ in range(1 + index % 3):
                data[rng.randrange(14, len(data))] = rng.randrange(256)
            if index % 2:
                del data[rng.randrange(len(data)):]
            with self.subTest(index=index):
                r = parse(bytes(data), len(bases[index % len(bases)]))
                self.assertIn(r.status, statuses)
                self.assertEqual((r.capture_id, r.packet_index), ("synthetic", 1))
                json.dumps(r.to_dict())
                if r.status == "malformed":
                    self.assertIsNone(r.src_port)
                    self.assertIsNone(r.dst_port)


class PrivacyReviewTests(unittest.TestCase):
    def test_malformed_then_valid_packet_retains_only_schema_metadata(self):
        marker = b"SYNTHETIC_PRIVATE_SENTINEL"
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "SYNTHETIC_PRIVATE_FILENAME.pcap"
            destination = Path(root) / "result.jsonl"
            malformed = ethernet(ipv6(bytes([17, 255]) + marker, 60), 0x86DD)
            source.write_bytes(capture(malformed, ethernet(ipv4(tcp(marker)))))
            stderr, stdout = io.StringIO(), io.StringIO()
            with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
                code = main(["--input", str(source), "--output", str(destination)])
            self.assertEqual(code, 0)
            text = destination.read_text()
            rows = [json.loads(line) for line in text.splitlines()]
            self.assertEqual([r["status"] for r in rows], ["malformed", "complete"])
            allowed = {"capture_id", "packet_index", "timestamp_ns", "packet_length", "captured_length",
                       "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "ip_protocol", "fragmented", "status"}
            for row in rows:
                self.assertEqual(set(row), allowed)
            exported = text + stdout.getvalue() + stderr.getvalue()
            for secret in (marker.decode(), marker.hex(), str(source), source.name, str(root)):
                self.assertNotIn(secret, exported)
            self.assertEqual(stdout.getvalue(), "")

    def test_fatal_framing_failure_logs_no_packet_or_filename_data(self):
        marker = b"SYNTHETIC_PRIVATE_SENTINEL"
        with tempfile.TemporaryDirectory() as root:
            source, destination = Path(root) / "PRIVATE.pcap", Path(root) / "result.jsonl"
            source.write_bytes(pcap_header() + packet_record(ethernet(ipv4(tcp(marker)))) + marker)
            log = io.StringIO()
            with contextlib.redirect_stderr(log):
                code = main(["--input", str(source), "--output", str(destination)])
            self.assertEqual(code, 1)
            self.assertNotIn(marker.decode(), log.getvalue())
            self.assertNotIn(str(root), log.getvalue())
            self.assertFalse(destination.exists())
            self.assertEqual(list(Path(root).glob(".sentinelforge-*.tmp")), [])
