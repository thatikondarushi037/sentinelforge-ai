# SentinelForge AI

SentinelForge AI is a network security investigation platform under development.
Milestone 1 provides its offline packet metadata engine; AI features are outside
this milestone. Use only authorized or synthetic captures. The current engine
is a tested foundation, not a claim of production readiness.

## Milestone 1

Stream classic Ethernet PCAP files into metadata-only JSONL containing exact
capture timestamps, source/destination IPs and ports, protocol, frame lengths,
a random capture identifier, packet index, and explicit parsing status. Missing
information is null. Packet payloads, credentials, and input paths are not
exported. The reader limits captured records to 1 MiB and bounds header traversal.
Output is private and published atomically without overwriting existing files.

The completed review passed 53 tests, including 15 added regressions and 2,000
deterministic malformed-packet mutations. TShark independently matched 96
synthetic packet records. Eight-process publication races produced one winner
and seven overwrite refusals. Memory measurements and their limits are recorded
in the [Milestone 1 engineering report](reports/milestone-01-packet-intelligence.md).

## Install and run

Verified on Ubuntu 24.04 with Python 3.12. Runtime dependency: `dpkt==1.9.8`.
Atomic publication requires Linux `renameat2(RENAME_NOREPLACE)` support.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
mkdir -p data/metadata
.venv/bin/python -m sentinelforge \
  --input /path/to/authorized.pcap \
  --output data/metadata/investigation.jsonl
```

Replace the input path with an authorized capture. The destination directory
must exist and the output file must not exist. The installed `sentinelforge`
command accepts the same arguments. Parsing needs no capture privileges.

## Verify

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m tests.verify_synthetic
.venv/bin/python -m pip check
git diff --check
```

The unittest suite uses only the standard library. The independent comparison
requires installed TShark; the memory smoke measurement uses `/usr/bin/time`
when available. The verification module generates synthetic inputs and outputs
in a private `/tmp` directory and prints its location. Keep virtual environments,
captures, secrets, generated JSONL, and temporary artifacts out of Git.

## Scope and limitations

Classic Ethernet PCAP only: no PCAPNG, live capture, reassembly, checksum
validation, tunnel decoding, or application parsing. Abrupt process/VM
termination can leave private temporary metadata; atomic visibility does not
guarantee power-loss durability. The report documents the architecture, complete
schema, error semantics, corrected IPv6 defects, measured results, exact
verification methodology, and remaining limitations. ML, RAG, orchestration,
containers, and databases are not included.
