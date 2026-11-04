"""Private temporary output, published only on successful completion."""
import json
import ctypes
import os
import tempfile
from pathlib import Path


def rename_noreplace(source, destination):
    """Linux renameat2: atomic rename with kernel-enforced no replacement."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1):
        code = ctypes.get_errno()
        raise OSError(code, "atomic_publish_failed")


def write_atomic(destination, records):
    destination = Path(destination)
    if os.path.lexists(destination):
        raise FileExistsError
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent,
                                         prefix=".sentinelforge-", suffix=".tmp",
                                         delete=False) as stream:
            temporary = Path(stream.name)
            count = 0
            for record in records:
                stream.write(json.dumps(record.to_dict(), separators=(",", ":")) + "\n")
                count += 1
            stream.flush()
            os.fsync(stream.fileno())
        rename_noreplace(temporary, destination)
        return count
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
