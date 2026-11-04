"""Offline CLI; exception details and input paths are never logged."""
import argparse
import sys
import uuid
from .decoder import decode
from .pcap_reader import CaptureError, read_packets
from .writer import write_atomic


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, "sentinelforge: invalid_arguments\n")


def main(argv=None):
    parser = SafeParser(description="Extract metadata from an authorized offline PCAP.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    capture_id = uuid.uuid4().hex
    try:
        with open(args.input, "rb") as source:
            count = write_atomic(args.output, (decode(packet, capture_id) for packet in read_packets(source)))
    except CaptureError as exc:
        print(f"sentinelforge: {exc}", file=sys.stderr)
        return 1
    except FileExistsError:
        print("sentinelforge: output_exists", file=sys.stderr)
        return 1
    except OSError:
        print("sentinelforge: io_error", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("sentinelforge: interrupted", file=sys.stderr)
        return 130
    except Exception:
        print("sentinelforge: processing_error", file=sys.stderr)
        return 1
    print(f"sentinelforge: complete records={count}", file=sys.stderr)
    return 0
