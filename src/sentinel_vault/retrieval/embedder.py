"""Embedders. Always run on **tokenized** text, so vectors never encode raw PII.

- ``HashEmbedder``: deterministic feature hashing. Offline, fast; used by tests and the
  default demo. Lexical, not semantic.
- ``FastEmbedEmbedder``: ONNX ``BAAI/bge-small-en-v1.5`` via ``fastembed`` (downloads
  ~130 MB on first use).
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import Sequence
from typing import Protocol

import numpy as np
import numpy.typing as npt

Vector = npt.NDArray[np.float32]
_WORD = re.compile(r"[a-z0-9_]+")


class Embedder(Protocol):
    dim: int

    async def embed(self, texts: Sequence[str]) -> Vector: ...


class HashEmbedder:
    def __init__(self, dim: int = 256) -> None:
        self.dim = dim

    def _one(self, text: str) -> Vector:
        v = np.zeros(self.dim, dtype=np.float32)
        for w in _WORD.findall(text.lower()):
            h = int.from_bytes(hashlib.blake2b(w.encode(), digest_size=8).digest(), "big")
            v[h % self.dim] += 1.0 if (h >> 63) & 1 else -1.0
        n = float(np.linalg.norm(v))
        return v / n if n else v

    async def embed(self, texts: Sequence[str]) -> Vector:
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)
        return np.stack([self._one(t) for t in texts])


class FastEmbedEmbedder:  # pragma: no cover - needs a model download; exercised manually
    def __init__(self, model: str = "BAAI/bge-small-en-v1.5") -> None:
        from fastembed import TextEmbedding

        self._model = TextEmbedding(model_name=model)
        self.dim = 384

    async def embed(self, texts: Sequence[str]) -> Vector:
        def run() -> Vector:
            return np.asarray(list(self._model.embed(list(texts))), dtype=np.float32)

        return await asyncio.to_thread(run)


def build_embedder(kind: str) -> Embedder:
    return FastEmbedEmbedder() if kind == "fastembed" else HashEmbedder()  # pragma: no branch
