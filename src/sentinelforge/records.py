"""Only these fields may leave the decoder."""
from dataclasses import asdict, dataclass
from typing import Literal

Status = Literal["complete", "truncated", "malformed", "unsupported", "non_ip"]


@dataclass(slots=True)
class Record:
    capture_id: str
    packet_index: int
    timestamp_ns: int
    packet_length: int
    captured_length: int
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    ip_protocol: int | None = None
    fragmented: bool | None = None
    status: Status = "complete"

    def to_dict(self):
        return asdict(self)
