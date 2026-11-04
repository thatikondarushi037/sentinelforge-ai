# Milestone 1: Offline Packet Intelligence Engine

## Engineering summary

SentinelForge AI is being developed as an AI-powered network security
investigation platform. This milestone establishes its deterministic packet
metadata foundation. It reads authorized or synthetic offline captures and
produces structured records without exporting packet payloads. AI, retrieval,
workflow orchestration, containers, and database storage are outside this
milestone.

The implementation and review were performed on Ubuntu 24.04.4 with Python
3.12.3, four logical CPUs, and approximately 11 GiB of usable RAM in the
user's VirtualBox environment. The design targets the stated maximum of
12 GB RAM and four vCPUs. The measured checks below support this milestone's
behavior on the exercised inputs; they do not establish production readiness.

## Problem statement and objective

Security investigation needs consistent packet timestamps, network endpoints,
transport ports, protocol identifiers, and frame lengths. Reading an entire
capture into a list can consume memory proportional to capture size. Exporting
packet objects or arbitrary dissector fields can also persist credentials or
application content unintentionally.

The objective is a small offline engine that streams capture records into a
fixed metadata schema, preserves uncertainty as null values, handles malformed
inputs safely, and publishes output only after successful completion. Existing
outputs must never be overwritten, including when independent writers race.

## Architecture and modules

```text
Authorized/synthetic classic PCAP
    -> strict container reader
    -> bounded link/IP/transport header decoder
    -> metadata-only Record
    -> private temporary JSONL file
    -> flush + fsync + atomic no-replacement rename
```

| Module/file | Responsibility |
| --- | --- |
| `src/sentinelforge/pcap_reader.py` | Validate global/record headers, enforce allocation bounds, preserve exact timestamps and original lengths, and yield packets in file order |
| `src/sentinelforge/decoder.py` | Decode supported outer headers; classify packet status; prevent payload decoding and incomplete-port extraction |
| `src/sentinelforge/records.py` | Define the allowlisted JSONL fields and nullable metadata model |
| `src/sentinelforge/writer.py` | Serialize one record at a time; create private temporary output; publish atomically without replacement; clean up handled failures |
| `src/sentinelforge/cli.py` | Parse arguments, assign a random capture ID, connect the pipeline, and emit sanitized status/error messages |
| `src/sentinelforge/__main__.py` | Provide the `python -m sentinelforge` entry point |
| `src/sentinelforge/__init__.py` | Identify the importable package |
| `tests/synthetic.py` | Independently construct capture and packet bytes with standard-library tools |
| `tests/test_pcap_reader.py`, `test_decoder.py`, `test_cli.py` | Exercise container validation, decoding, CLI behavior, publication, and privacy |
| `tests/test_review.py` | Add targeted review regressions, malformed mutations, and actual multiprocess publication races |
| `tests/verify_synthetic.py` | Run the CLI, compare fields with TShark, and measure memory in fresh processes |
| `pyproject.toml` | Declare Python support, package discovery, console entry point, and pinned runtime dependency |

## Capture, parsing, and PCAP internals

Packet capture collects bytes from a network interface through operating-system
facilities, commonly exposed by libpcap. Capture can require additional
privileges, drop traffic under load, and save only a configured snapshot of
each frame. Packet parsing interprets bytes already present in a file. This
engine performs parsing only, needs ordinary file permissions, and does not
open a capture interface or make network requests.

A classic-PCAP global header identifies the format, byte order, timestamp
resolution, snapshot length, and link type. Each following packet header
contains seconds, a fractional timestamp, captured length, and original frame
length. The reader supports version 2.4, both byte orders, and microsecond or
nanosecond resolution. It converts timestamps to integer epoch nanoseconds
without floating-point rounding. Source precision and clock accuracy are not
improved by that representation, and timestamp order is not assumed monotonic.

Before reading a packet body, the reader checks that its captured length is
at most 1 MiB and no greater than either snapshot length or original length.
Invalid timestamp fractions, incomplete headers/bodies, unsupported link types,
and PCAPNG produce fatal, fixed-code errors. No boundary recovery is attempted
after container corruption. A valid empty capture produces an empty output.

The decoder follows Ethernet and at most four VLAN tags into IPv4 or IPv6.
It supports TCP, UDP, ICMP, and ICMPv6 metadata. IPv6 traversal supports
Hop-by-Hop Options, Routing, Fragment, Authentication, and Destination Options
headers, with a maximum of eight extension headers. ESP and other unsupported
protocols are classified explicitly. Only outer headers are investigated.

## Design decisions and dependency tradeoffs

The only runtime dependency is `dpkt==1.9.8`. The package uses the standard
library for framing, IP address normalization, dataclasses, JSON, CLI arguments,
temporary files, and UUID generation. Tests use `unittest`; build tooling uses
setuptools. Python 3.12 is the verified interpreter baseline.

dpkt supplies established fixed-header definitions. The decoder calls
`dpkt.Packet.unpack` for fixed IP headers rather than invoking dpkt's automatic
IP payload/extension decoding. TCP and UDP receive only their validated header
slices. This keeps payloads out of protocol-specific application parsers and
puts traversal limits under this engine's control.

The small custom PCAP reader makes length checks occur before body allocation
and retains original frame length explicitly. Reimplementing the whole
protocol stack would increase maintenance and correctness obligations. Scapy
offers a broader packet construction and manipulation interface than this
milestone needs. TShark offers many more dissectors and capture formats, but
would add an external runtime and subprocess/output contract to the engine;
it is used here as an independent verification tool.

## Bounded-memory streaming

The pipeline processes one record at a time with bounded transient buffers.
There is no packet list, growing flow table, reassembly cache, or per-packet
error collection. A 1 MiB maximum captured record bounds packet-body reads;
fixed-header slices and explicit VLAN/extension limits bound decoding work.
The total process RSS is not limited to 1 MiB: Python, dependencies, serialization,
and transient buffers also consume memory. Output disk usage grows with packet
count. Slow writes naturally delay input processing rather than growing a queue.

This is a design argument for memory independent of packet count, supported by
the specific smoke measurements below. It is not a universal RSS or throughput
guarantee, an OS-enforced memory limit, or a comprehensive adversarial benchmark.

## JSONL schema and status semantics

Every line is a JSON object with the following fields. Missing information is
JSON `null`, never a guessed endpoint, port, or protocol.

| Field | Type and meaning |
| --- | --- |
| `capture_id` | String: random UUID hex shared within one invocation; not a path, filename, content hash, or stable cross-run identity |
| `packet_index` | Integer: one-based file order, including malformed and non-IP packets |
| `timestamp_ns` | Integer: Unix epoch nanoseconds at source precision |
| `packet_length` | Integer: original frame length reported by PCAP, including the link header |
| `captured_length` | Integer: number of bytes saved in this packet record |
| `src_ip`, `dst_ip` | String or null: normalized outer IPv4/IPv6 addresses |
| `src_port`, `dst_port` | Integer or null: ports from complete TCP/UDP headers |
| `protocol` | String or null: TCP, UDP, ICMP, ICMPv6, or decimal protocol identifier |
| `ip_protocol` | Integer or null: IP protocol/next-header identifier reached by traversal |
| `fragmented` | Boolean or null: fragment indication; IPv6 atomic fragments are true |
| `status` | String: one of the five categories below |

* `complete`: supported headers are readable and consistent with the checks
  performed. This is not a checksum or full RFC-validity certificate.
* `truncated`: capture bytes are fewer than the reported original frame length,
  including when required header bytes are unavailable within that snapshot.
* `malformed`: invalid or contradictory header lengths or checked structural
  rules; also missing required bytes in an otherwise nontruncated frame.
* `unsupported`: unsupported protocols, traversal limits, or unsupported
  zero-payload-length IPv6 cases other than No Next Header.
* `non_ip`: an Ethernet payload other than IPv4/IPv6; IP, protocol, and port
  fields remain null.

Malformed, unsupported, and non-IP classifications take precedence over capture
truncation. The two length fields retain the capture-truncation evidence.
Packet classifications allow processing to continue; fatal container errors
abort publication. For a noninitial IPv6 fragment, `ip_protocol` may identify
an extension header: fragment data is not traversed to infer later headers.

TCP ports require the entire declared TCP header, including options. UDP ports
require its complete eight-byte header and a consistent length. A first fragment
can contain a UDP header whose datagram continues in later fragments. Noninitial
fragments never yield ports. Trailing IP bytes beyond UDP length are ignored.

## Privacy, failure handling, and atomic publication

The export schema contains no payload field, raw bytes, arbitrary packet
representation, input path, filename, MAC address, DNS name, or application
content. Existing input bytes may contain credentials and necessarily pass
through memory; the parser does not persist them or create a capture copy.
Synthetic sentinel content is used in temporary unit-test inputs to check
that it cannot appear in exported metadata or logs.

Errors use fixed codes without arbitrary exception details. CLI argument
errors do not echo supplied values. Output files are mode `0600`. Git ignore
rules exclude virtual environments, captures, local secrets, generated JSONL,
temporary files, and build artifacts; only explicitly reviewed files are
staged. Ignore rules are convenience controls, not secret detection or access
control. IP addresses and timestamps remain sensitive metadata and require
appropriate handling. Use only authorized/synthetic inputs and a trusted
destination directory; this milestone is not a sandbox for hostile users.

The writer creates a private temporary file in the destination directory,
streams JSONL, flushes buffers, and calls `fsync` on the file. Only after all
records have been processed does Linux `renameat2(RENAME_NOREPLACE)` atomically
publish it. The syscall refuses a destination created after the initial
existence check, so correctness does not depend on a check-then-write race.
An existing file or symlink is refused, with no overwrite option.

Handled framing, decoding-pipeline, I/O, flush, rename, and keyboard-interrupt
failures remove this run's temporary output. Malformed packet statuses are not
fatal pipeline errors. Unsupported atomic-rename facilities fail closed. The
destination directory must already exist. CLI exit codes are 0 for successful
publication, 1 for processing/I/O failure, 2 for argument errors, and 130 for
keyboard interruption.

## Review findings and corrections

The first implementation's automatic dpkt IPv6 unpacking attempted extension
decoding before the engine's traversal; four initial tests exposed that problem.
Using fixed-header unpacking removed the eager behavior and left bounds under
explicit control. A subsequent independent review pass found these additional
issues and added reproducing regressions before correction:

| Finding | Correction |
| --- | --- |
| Valid empty IPv6 No Next Header packets were marked unsupported | Accept zero payload length when the base Next Header is 59 |
| IPv6 chains could incorrectly report `fragmented=false` before traversal was complete | Keep fragmentation unknown unless absence is established or a complete Fragment header is seen |
| Misplaced/repeated Hop-by-Hop Options could be accepted | Require that header immediately after the IPv6 base header |
| Misaligned nonfinal fragments could be marked complete | Require nonempty fragment data aligned to eight bytes for checked IPv4/IPv6 nonfinal fragments |
| UDP trailing IP padding was treated as a contradictory length | Accept padding while never reading it as application metadata |
| IPv4 protocol 59 inherited IPv6 No Next Header handling | Restrict that supported termination case to IPv6 |

Regressions also cover duplicate Fragment headers, extension lengths crossing
the declared IP boundary into Ethernet padding, incomplete IPv6 TCP options,
and noninitial fragments containing bytes that resemble transport headers.
Protocol guidance was checked against [RFC 8200](https://www.rfc-editor.org/rfc/rfc8200.html),
[RFC 791](https://www.rfc-editor.org/rfc/rfc791.html), and
[RFC 768](https://www.rfc-editor.org/rfc/rfc768.html). Atomic publication uses the
documented [Linux renameat2 interface](https://man7.org/linux/man-pages/man2/rename.2.html).

## Reported verification measurements

These are the recorded results of the completed quality-review run, not
predictions for future runs. No real network capture was needed for these checks.

| Check | Recorded result |
| --- | --- |
| Full unit suite | 53 tests passed, zero remaining failures/errors; final reviewed run took 0.539 seconds |
| Added review regressions | 15 test methods added to the original 38-test suite |
| Independent TShark comparison | 96 synthetic packet records: 24 cases across little/big endian and microsecond/nanosecond PCAP variants; all eight compared metadata fields and protocol numbers matched |
| Malformed mutation exercise | 2,000 deterministic mutations, seed 20261104; no uncaught decoding errors; malformed classifications emitted no ports |
| Concurrent publication | Eight spawned writers synchronized before publication; one success and seven overwrite refusals; exact winner content, mode 0600, no temporary output left, and no partial output observed by a concurrent reader |
| Additional concurrency stress | Five more eight-writer rounds passed with the same outcome |
| Dependency and whitespace checks | `pip check`, `git diff --check`, and checks covering new source/configuration files passed |

The comparison covers packet index, timestamp, source/destination IPs,
source/destination ports, original length, and captured length, plus numeric
protocol. It does not compare capture UUIDs or establish exhaustive agreement
on malformed-packet classifications. TShark can expose fields from partial
headers that this engine deliberately leaves null. Synthetic fixtures are
constructed independently using `struct` and `ipaddress`, without dpkt. Some
synthetic checksums are placeholders; checksum validation is outside scope.

| Memory workload | Capture bytes | Peak RSS | Elapsed time |
| --- | ---: | ---: | ---: |
| 1,000 repeated synthetic Ethernet/IPv4/TCP header records | 70,024 | 20,224 KiB | 0.10 seconds |
| 200,000 of the same records | 14,000,024 | 20,312 KiB | 3.68 seconds |

Each memory measurement starts a fresh CLI process through `/usr/bin/time`.
Input generation precedes timing. The timed process includes parsing,
serialization, output writes, file fsync, and publication; output line counting
occurs afterward and must match the input count. The fixture is a 54-byte frame
plus a 16-byte PCAP record header, repeated after a 24-byte global header. No
packet list is created in the timed CLI. Filesystem cache state, VM scheduling,
and system load were not controlled; there are no statistical repetitions or
confidence intervals for these memory/time observations. The 88 KiB RSS
difference supports stable memory for this workload, not general performance
or security claims.

An auxiliary stress launcher initially failed because Python multiprocessing
`spawn` cannot reload a script supplied through stdin. It was stopped and
rerun through `python -m unittest`; all five corrected rounds passed. This was
a verification-launcher issue, not an unresolved engine test failure.

### Pre-commit verification rerun

The documentation/commit preparation reran the same full suite and verification
module successfully: 53 tests passed in 0.831 seconds, all 96 TShark comparisons
matched, and `pip check` and `git diff --check` passed. The concurrency and 2,000
mutation checks were included in that suite. The new synthetic artifact
directory was `/tmp/sentinelforge-verification-bds4elu3`.

The fresh smoke measurements were 20,168 KiB RSS and 0.22 seconds for 1,000
packets, and 20,336 KiB RSS and 5.00 seconds for 200,000 packets. These are
additional observations, not replacements for the previously reported
20,224/20,312 KiB and 3.68-second results. Timing/RSS variation reinforces the
need to avoid treating either run as a general performance guarantee.

## Reproducible verification and benchmark commands

From the repository root, with Python 3.12 and installed TShark:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m tests.verify_synthetic
.venv/bin/python -m pip check
git diff --check
git status --short
```

The verification module generates only synthetic artifacts under a newly
created private `/tmp/sentinelforge-verification-*` directory and prints that
directory. It performs all four TShark variants and both memory workloads.
Run normally, without Python's `-O` flag, because its verification assertions
must remain enabled. It leaves generated artifacts for local review; none
belongs in the repository.

Its exact timing command structure, expressed as shell arguments, is:

```bash
/usr/bin/time -f 'peak_rss_kib=%M elapsed_seconds=%e' \
  .venv/bin/python -m sentinelforge \
  --input /tmp/sentinelforge-verification-RUN/memory-1000.pcap \
  --output /tmp/sentinelforge-verification-RUN/memory-1000.jsonl

/usr/bin/time -f 'peak_rss_kib=%M elapsed_seconds=%e' \
  .venv/bin/python -m sentinelforge \
  --input /tmp/sentinelforge-verification-RUN/memory-200000.pcap \
  --output /tmp/sentinelforge-verification-RUN/memory-200000.jsonl
```

`RUN` denotes the generated directory suffix, not a literal existing path.
The Python runner uses `sys.executable`, resolving to the virtual-environment
interpreter. For the reported review measurements, the generated directory was
`/tmp/sentinelforge-verification-_9z69x00`. To rerun timings manually, generate
fresh inputs/output names with the verification module; output overwrite is
intentionally refused.

The metadata comparison invokes TShark with this argument structure for each
generated PCAP:

```bash
tshark -n -r /tmp/sentinelforge-verification-RUN/synthetic-le-us.pcap \
  -o ip.defragment:FALSE -o ipv6.defragment:FALSE \
  -T fields -E occurrence=f \
  -e frame.number -e frame.time_epoch \
  -e ip.src -e ipv6.src -e ip.dst -e ipv6.dst \
  -e tcp.srcport -e udp.srcport -e tcp.dstport -e udp.dstport \
  -e frame.len -e frame.cap_len
```

The second TShark pass uses the same input, disabled reassembly, and `-T fields`,
with `-e ip.proto -e ipv6.nxt -e ipv6.hopopts.nxt -e ipv6.routing.nxt
-e ipv6.fraghdr.nxt -e ah.next_header -e ipv6.dstopts.nxt`. The verifier follows
these independently dissected next-header values, preserving repeated headers,
to compare the reached protocol. Timestamp comparison uses `Decimal` rather
than binary floating point. The other files are `synthetic-le-ns.pcap`,
`synthetic-be-us.pcap`, and `synthetic-be-ns.pcap`.

The concurrency regression can be reproduced directly:

```bash
.venv/bin/python -m unittest -v \
  tests.test_review.PublicationReviewTests.test_eight_concurrent_processes_publish_exactly_one_complete_file
```

For the five additional stress rounds, the same test name was supplied five
times to that `python -m unittest -v` invocation. Use the module entry point,
not a stdin-based Python launcher, so spawned workers can reload it.

## Remaining limitations and security considerations

* Classic Ethernet PCAP only: no PCAPNG, Linux cooked/loopback link types,
  compressed capture input, or live capture.
* No tunnel inner-packet decoding, fragment reassembly, TCP stream
  reconstruction, application parsing, checksum validation, or comprehensive
  RFC conformance validation. Length/traversal limits can classify legitimate
  unusual traffic as unsupported. Jumbograms remain unsupported.
* No OS-enforced resource sandbox or maximum total input/output size; callers
  must provision disk space and control access to untrusted files. The 1 MiB
  bound applies to captured records, not original length metadata or total RSS.
* Linux/libc/filesystem support for `renameat2(RENAME_NOREPLACE)` is required.
  The tested concurrent-writer behavior is not a portability claim for other
  operating systems or untested filesystems.
* File fsync and atomic visibility do not guarantee power-loss durability of
  the directory entry: the destination directory is not fsynced. SIGKILL,
  default SIGTERM termination, VM crashes, or power loss cannot run normal
  cleanup and may leave private temporary metadata. Existing files are never
  automatically deleted to recover from these situations.
* The regression corpus and mutation exercise are finite checks, not exhaustive
  fuzzing, formal verification, a security audit certification, or evidence of
  production readiness. No discovered milestone defect remained unresolved
  after the recorded review.

## Milestone outcome

The milestone delivers a reproducible offline packet metadata foundation with
explicit limits, tested uncertainty handling, and atomic no-overwrite output.
Further platform capabilities require separate scope, design, and validation.
