"""Decode calldata for the functions that matter when approving or moving assets."""

from __future__ import annotations

from dataclasses import dataclass

from signcheck.eip712 import checksum
from signcheck.keccak import keccak256

SIGNATURES = [
    # ERC-20 / ERC-721 / ERC-1155
    "approve(address spender,uint256 amount)",
    "increaseAllowance(address spender,uint256 amount)",
    "transfer(address to,uint256 amount)",
    "transferFrom(address from,address to,uint256 amount)",
    "setApprovalForAll(address operator,bool approved)",
    "safeTransferFrom(address from,address to,uint256 tokenId)",
    "safeTransferFrom(address from,address to,uint256 tokenId,bytes data)",
    "safeTransferFrom(address from,address to,uint256 id,uint256 amount,bytes data)",
    # Permit2
    "approve(address token,address spender,uint160 amount,uint48 expiration)",
    # Safe settings
    "addOwnerWithThreshold(address owner,uint256 threshold)",
    "removeOwner(address prevOwner,address owner,uint256 threshold)",
    "swapOwner(address prevOwner,address oldOwner,address newOwner)",
    "changeThreshold(uint256 threshold)",
    "enableModule(address module)",
    "disableModule(address prevModule,address module)",
    "setGuard(address guard)",
    "setFallbackHandler(address handler)",
    "changeMasterCopy(address masterCopy)",
    "multiSend(bytes transactions)",
]


@dataclass
class Call:
    name: str
    signature: str
    args: dict


def _split(sig: str) -> tuple[str, list[tuple[str, str]]]:
    name, rest = sig.split("(", 1)
    params = [p.split(" ") for p in rest.rstrip(")").split(",") if p]
    return name, [(t, n) for t, n in params]


def selector(signature: str) -> bytes:
    """First 4 bytes of keccak256 of the canonical signature, e.g. approve(address,uint256)."""
    name, params = _split(signature) if " " in signature else (signature, None)
    canonical = f"{name}({','.join(t for t, _ in params)})" if params is not None else signature
    return keccak256(canonical.encode())[:4]


FUNCTIONS = {selector(s): s for s in SIGNATURES}


def _word(data: bytes, i: int) -> bytes:
    w = data[i : i + 32]
    if len(w) != 32:
        raise ValueError("calldata is too short")
    return w


def decode(data: bytes) -> Call | None:
    """The known function this calldata calls, or None. Raises ValueError for malformed arguments."""
    sig = FUNCTIONS.get(data[:4])
    if sig is None:
        return None
    name, params = _split(sig)
    body = data[4:]
    args = {}
    for i, (t, n) in enumerate(params):
        word = _word(body, 32 * i)
        value = int.from_bytes(word, "big")
        if t == "address":
            if value >> 160:
                raise ValueError(f"{n} is not an address")
            args[n] = checksum(value)
        elif t == "bool":
            if value > 1:
                raise ValueError(f"{n} is not a bool")
            args[n] = bool(value)
        elif t.startswith("uint"):
            if value >> int(t[4:] or 256):
                raise ValueError(f"{n} is out of range for {t}")
            args[n] = value
        elif t == "bytes":
            length = int.from_bytes(_word(body, value), "big")
            blob = body[value + 32 : value + 32 + length]
            if len(blob) != length:
                raise ValueError(f"{n} is cut short")
            args[n] = blob
    return Call(name, sig, args)


def multisend(data: bytes) -> list[tuple[int, str, int, bytes]]:
    """(operation, to, value, data) of each call packed into a Safe multiSend."""
    calls, i = [], 0
    while i < len(data):
        if i + 85 > len(data):
            raise ValueError("multiSend data is cut short")
        op = data[i]
        to = checksum(int.from_bytes(data[i + 1 : i + 21], "big"))
        value = int.from_bytes(data[i + 21 : i + 53], "big")
        n = int.from_bytes(data[i + 53 : i + 85], "big")
        call = data[i + 85 : i + 85 + n]
        if len(call) != n:
            raise ValueError("multiSend data is cut short")
        calls.append((op, to, value, call))
        i += 85 + n
    return calls
