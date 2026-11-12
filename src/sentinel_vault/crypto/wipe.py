"""Best-effort zeroing of key buffers.

Honest limit: Python can't guarantee no other copy exists (``bytes`` objects are
immutable, the allocator may have moved data, and ``cryptography`` copies the key into
OpenSSL/Rust). Keeping keys in ``bytearray`` and zeroing them on release shrinks the
window; it is not a guarantee. A production system would do this in a native sidecar
or enclave.
"""

from __future__ import annotations

import ctypes


def wipe(buf: bytearray) -> None:
    n = len(buf)
    if n:
        ctypes.memset((ctypes.c_char * n).from_buffer(buf), 0, n)


def is_wiped(buf: bytearray) -> bool:
    return not any(buf)
