"""EIP-712 typed data: parsing and the hashes a wallet signs."""

from __future__ import annotations

import json
import re

from signcheck.keccak import keccak256

_ARRAY = re.compile(r"^(.+)\[(\d*)\]$")
_INT = re.compile(r"^(u?)int(\d*)$")
_FIXED_BYTES = re.compile(r"^bytes(\d+)$")

# the order EIP-712 gives, used when a request leaves EIP712Domain out of `types` (viem, ethers do)
DOMAIN_FIELDS = [("name", "string"), ("version", "string"), ("chainId", "uint256"), ("verifyingContract", "address"), ("salt", "bytes32")]


class TypedDataError(ValueError):
    pass


def to_int(value) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        s = value.strip()
        try:
            return int(s, 16) if s.lower().startswith(("0x", "-0x")) else int(s)
        except ValueError:
            pass
    raise TypedDataError(f"not a number: {value!r}")


def to_bytes(value) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str) and value.lower().startswith("0x"):
        h = value[2:]
        try:
            return bytes.fromhex(h if len(h) % 2 == 0 else "0" + h)
        except ValueError:
            pass
    raise TypedDataError(f"not hex bytes: {value!r}")


def parse_address(value) -> int:
    if isinstance(value, str):
        s = value.strip()
        h = s[2:] if s.lower().startswith("0x") else s
        if re.fullmatch(r"[0-9a-fA-F]{1,40}", h):
            return int(h, 16)
    elif isinstance(value, int) and 0 <= value < 1 << 160:
        return value
    raise TypedDataError(f"not an address: {value!r}")


def checksum(value) -> str:
    """EIP-55 mixed-case address."""
    a = f"{parse_address(value):040x}"
    h = keccak256(a.encode()).hex()
    return "0x" + "".join(c.upper() if int(h[i], 16) >= 8 else c for i, c in enumerate(a))


def _base(t: str) -> str:
    while t.endswith("]"):
        t = t[: t.rindex("[")]
    return t


def _deps(t: str, types: dict, found: list[str]) -> list[str]:
    base = _base(t)
    if base in found or base not in types:
        return found
    found.append(base)
    for f in types[base]:
        _deps(f["type"], types, found)
    return found


def encode_type(primary: str, types: dict) -> str:
    deps = _deps(primary, types, [])[1:]
    return "".join(f"{name}({','.join(f['type'] + ' ' + f['name'] for f in types[name])})" for name in [primary, *sorted(deps)])


def _encode_value(t: str, value, types: dict) -> bytes:
    if t in types:
        return hash_struct(t, value, types)
    m = _ARRAY.match(t)
    if m:
        if not isinstance(value, list):
            raise TypedDataError(f"{t} needs a list, got {value!r}")
        if m[2] and len(value) != int(m[2]):
            raise TypedDataError(f"{t} needs {m[2]} items, got {len(value)}")
        return keccak256(b"".join(_encode_value(m[1], v, types) for v in value))
    if t == "string":
        if not isinstance(value, str):
            raise TypedDataError(f"string needs text, got {value!r}")
        return keccak256(value.encode())
    if t == "bytes":
        return keccak256(to_bytes(value))
    if t == "bool":
        if isinstance(value, str):
            value = value.strip().lower() in ("true", "1")
        return int(bool(value)).to_bytes(32, "big")
    if t == "address":
        return parse_address(value).to_bytes(32, "big")
    m = _INT.match(t)
    if m:
        bits = int(m[2] or 256)
        n = to_int(value)
        lo, hi = (0, 1 << bits) if m[1] else (-(1 << (bits - 1)), 1 << (bits - 1))
        if not lo <= n < hi:
            raise TypedDataError(f"{n} is out of range for {t}")
        return (n % (1 << 256)).to_bytes(32, "big")
    m = _FIXED_BYTES.match(t)
    if m:
        b = to_bytes(value)
        if len(b) > int(m[1]):
            raise TypedDataError(f"{value!r} is longer than {t}")
        return b.ljust(32, b"\0")
    raise TypedDataError(f"unknown type {t!r}")


def hash_struct(name: str, data, types: dict) -> bytes:
    if not isinstance(data, dict):
        raise TypedDataError(f"{name} needs an object, got {data!r}")
    parts = [keccak256(encode_type(name, types).encode())]
    for f in types[name]:
        if f["name"] not in data:
            raise TypedDataError(f"{name}.{f['name']} is missing")
        parts.append(_encode_value(f["type"], data[f["name"]], types))
    return keccak256(b"".join(parts))


def parse(obj) -> dict:
    """Normalise a typed-data request: a dict or its JSON text."""
    if isinstance(obj, str):
        try:
            obj = json.loads(obj)
        except json.JSONDecodeError as err:
            raise TypedDataError(f"typed data is not valid JSON: {err}") from None
    if not isinstance(obj, dict) or not {"types", "primaryType", "message"} <= obj.keys():
        raise TypedDataError("typed data needs types, primaryType and message (eth_signTypedData_v3/v4)")
    types = dict(obj["types"])
    domain = obj.get("domain") or {}
    if "EIP712Domain" not in types:
        types["EIP712Domain"] = [{"name": n, "type": t} for n, t in DOMAIN_FIELDS if n in domain]
    if obj["primaryType"] not in types:
        raise TypedDataError(f"primaryType {obj['primaryType']!r} is not in types")
    return {"types": types, "primaryType": obj["primaryType"], "domain": domain, "message": obj["message"]}


def hashes(td: dict) -> tuple[bytes, bytes | None, bytes]:
    """(domain separator, message hash, digest). Hardware wallets show the first two."""
    domain = hash_struct("EIP712Domain", td["domain"], td["types"])
    if td["primaryType"] == "EIP712Domain":
        return domain, None, keccak256(b"\x19\x01" + domain)
    message = hash_struct(td["primaryType"], td["message"], td["types"])
    return domain, message, keccak256(b"\x19\x01" + domain + message)
