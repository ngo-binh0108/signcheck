"""Keccak-256, the hash Ethereum uses.

This is the original Keccak padding, not NIST SHA3-256, so `hashlib.sha3_256`
gives different results. Pure Python: fast enough for signature requests.
"""

from __future__ import annotations

_MASK = (1 << 64) - 1
_RATE = 136  # bytes, for a 256-bit output


def _rol(a: int, n: int) -> int:
    n %= 64
    return ((a << n) | (a >> (64 - n))) & _MASK


def _round_constants() -> list[int]:
    out, r = [], 1
    for _ in range(24):
        c = 0
        for j in range(7):
            r = ((r << 1) ^ ((r >> 7) * 0x71)) % 256
            if r & 2:
                c ^= 1 << ((1 << j) - 1)
        out.append(c)
    return out


def _rho_pi() -> list[tuple[int, int]]:
    steps, x, y = [], 1, 0
    for t in range(24):
        x, y = y, (2 * x + 3 * y) % 5
        steps.append((x + 5 * y, (t + 1) * (t + 2) // 2))
    return steps


_RC = _round_constants()
_STEPS = _rho_pi()


def _permute(a: list[int]) -> None:
    for rc in _RC:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for i in range(25):
            a[i] ^= d[i % 5]
        cur = a[1]
        for i, rot in _STEPS:
            cur, a[i] = a[i], _rol(cur, rot)
        for y in range(0, 25, 5):
            t = a[y : y + 5]
            for x in range(5):
                a[y + x] = t[x] ^ (~t[(x + 1) % 5] & t[(x + 2) % 5])
        a[0] ^= rc


def keccak256(data: bytes) -> bytes:
    padded = bytearray(data) + b"\x01" + bytes((-len(data) - 1) % _RATE)
    padded[-1] |= 0x80
    state = [0] * 25
    for off in range(0, len(padded), _RATE):
        for i in range(_RATE // 8):
            state[i] ^= int.from_bytes(padded[off + 8 * i : off + 8 * i + 8], "little")
        _permute(state)
    return b"".join(state[i].to_bytes(8, "little") for i in range(4))
