import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from sentinelforge.cli import main
from sentinelforge.pcap_reader import CaptureError
from sentinelforge.writer import write_atomic
from sentinelforge.records import Record
from tests.synthetic import capture, ethernet, ipv4, pcap_header, samples, tcp


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "private-input.pcap"
        self.output = self.root / "metadata.jsonl"
        self.source.write_bytes(capture(*samples()))

    def run_cli(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = main(["--input", str(self.source), "--output", str(self.output)])
        return code, stderr.getvalue()

    def assert_no_temp(self):
        self.assertEqual(list(self.root.glob(".sentinelforge-*.tmp")), [])

    def test_success_identity_permissions_and_no_paths(self):
        code, log = self.run_cli()
        self.assertEqual(code, 0)
        rows = [json.loads(line) for line in self.output.read_text().splitlines()]
        self.assertEqual(len(rows), 7)
        self.assertEqual([r["packet_index"] for r in rows], list(range(1, 8)))
        self.assertEqual(len({r["capture_id"] for r in rows}), 1)
        self.assertEqual(len(rows[0]["capture_id"]), 32)
        self.assertNotIn(str(self.root), self.output.read_text() + log)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        self.assert_no_temp()

    def test_module_entry_point(self):
        result = subprocess.run([sys.executable, "-m", "sentinelforge", "--input", str(self.source),
                                 "--output", str(self.output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_refuse_overwrite(self):
        self.output.write_text("existing")
        self.assertEqual(self.run_cli()[0], 1)
        self.assertEqual(self.output.read_text(), "existing")
        self.assert_no_temp()

    def test_cleanup_after_late_framing_failure(self):
        self.source.write_bytes(capture(*samples()) + b"incomplete")
        code, log = self.run_cli()
        self.assertEqual(code, 1)
        self.assertIn("incomplete_packet_header", log)
        self.assertFalse(self.output.exists())
        self.assert_no_temp()

    def test_missing_input_does_not_log_path(self):
        self.source = self.root / "SYNTHETIC_CREDENTIAL"
        code, log = self.run_cli()
        self.assertEqual(code, 1)
        self.assertNotIn("SYNTHETIC_CREDENTIAL", log)
        self.assert_no_temp()

    def test_invalid_argument_does_not_echo_sensitive_text(self):
        stream = io.StringIO()
        with contextlib.redirect_stderr(stream), self.assertRaises(SystemExit):
            main(["SYNTHETIC_CREDENTIAL"])
        self.assertNotIn("SYNTHETIC_CREDENTIAL", stream.getvalue())

    def test_empty_capture(self):
        self.source.write_bytes(pcap_header())
        self.assertEqual(self.run_cli()[0], 0)
        self.assertEqual(self.output.read_bytes(), b"")

    def test_status_records_are_successful_completion(self):
        self.source.write_bytes(capture(ethernet(bytes(28), 0x0806), b"short"))
        self.assertEqual(self.run_cli()[0], 0)
        rows = [json.loads(s) for s in self.output.read_text().splitlines()]
        self.assertEqual([r["status"] for r in rows], ["non_ip", "malformed"])

    def test_payload_absent_from_output_and_logs(self):
        marker = b"SYNTHETIC_CREDENTIAL"
        self.source.write_bytes(capture(ethernet(ipv4(tcp(marker)))))
        code, log = self.run_cli()
        self.assertEqual(code, 0)
        self.assertNotIn(marker.decode(), self.output.read_text() + log)

    def test_destination_invisible_until_completion(self):
        def records():
            yield Record("synthetic", 1, 0, 0, 0)
            self.assertFalse(self.output.exists())
            temps = list(self.root.glob(".sentinelforge-*.tmp"))
            self.assertEqual(len(temps), 1)
            self.assertEqual(temps[0].stat().st_mode & 0o777, 0o600)
        write_atomic(self.output, records())
        self.assertTrue(self.output.exists())
        self.assert_no_temp()

    def test_concurrent_destination_creation_not_overwritten(self):
        def records():
            yield Record("synthetic", 1, 0, 0, 0)
            self.output.write_text("racing creator")
        with self.assertRaises(FileExistsError):
            write_atomic(self.output, records())
        self.assertEqual(self.output.read_text(), "racing creator")
        self.assert_no_temp()

    def test_cleanup_on_interrupt_and_unexpected_failure(self):
        for failure in [KeyboardInterrupt(), RuntimeError("SYNTHETIC_CREDENTIAL")]:
            with self.subTest(failure=type(failure).__name__):
                def records():
                    yield Record("synthetic", 1, 0, 0, 0)
                    raise failure
                with self.assertRaises(type(failure)):
                    write_atomic(self.output, records())
                self.assertFalse(self.output.exists())
                self.assert_no_temp()

    def test_fsync_failure_cleans_output(self):
        with patch("sentinelforge.writer.os.fsync", side_effect=OSError("sensitive")):
            code, log = self.run_cli()
        self.assertEqual(code, 1)
        self.assertNotIn("sensitive", log)
        self.assertFalse(self.output.exists())
        self.assert_no_temp()

    def test_symlink_output_refused(self):
        self.output.symlink_to(self.root / "missing")
        self.assertEqual(self.run_cli()[0], 1)
        self.assertTrue(self.output.is_symlink())
