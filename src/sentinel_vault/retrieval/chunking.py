"""Chunking and chunk payload encoding."""

from __future__ import annotations

import re
import struct

import numpy as np

from sentinel_vault.retrieval.embedder import Vector

_PIECES = re.compile(r"\S+|\s+")
_MAGIC = b"SVC1"


def chunk_text(text: str, size: int, overlap: int) -> list[str]:
    """Split on whitespace into chunks of <= ``size`` chars with ~``overlap`` chars repeated.

    Splitting only at whitespace keeps ``<<TOKEN_...>>`` placeholders whole.
    """
    words = [w for w in _PIECES.findall(text) if not w.isspace()]
    chunks: list[str] = []
    cur: list[str] = []
    cur_len = 0
    for w in words:
        if len(w) > size:  # one giant "word": hard split
            if cur:
                chunks.append(" ".join(cur))
                cur, cur_len = [], 0
            chunks.extend(w[i:i + size] for i in range(0, len(w), size))
            continue
        if cur and cur_len + 1 + len(w) > size:
            chunks.append(" ".join(cur))
            tail: list[str] = []
            tail_len = 0
            for x in reversed(cur):
                if tail_len + len(x) + 1 > overlap:
                    break
                tail.insert(0, x)
                tail_len += len(x) + 1
            cur, cur_len = tail, max(tail_len - 1, 0)
        cur.append(w)
        cur_len += len(w) + (1 if cur_len else 0)
    if cur:
        chunks.append(" ".join(cur))
    return chunks


def encode_chunk(text: str, vec: Vector) -> bytes:
    t = text.encode("utf-8")
    return _MAGIC + struct.pack(">II", len(t), vec.shape[0]) + t + vec.astype(">f4").tobytes()


def decode_chunk(data: bytes) -> tuple[str, Vector]:
    if data[:4] != _MAGIC:
        raise ValueError("bad chunk payload")
    tlen, dim = struct.unpack(">II", data[4:12])
    text = data[12:12 + tlen].decode("utf-8")
    vec = np.frombuffer(data[12 + tlen:12 + tlen + 4 * dim], dtype=">f4").astype(np.float32)
    return text, vec
