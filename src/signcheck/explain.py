"""Turn a signature or transaction request into plain fields and risk findings."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from signcheck import abi, eip712, known, router
from signcheck.eip712 import TypedDataError, checksum, to_bytes, to_int
from signcheck.keccak import keccak256

MAX_UINT160 = (1 << 160) - 1
YEAR = 365 * 24 * 3600
NEVER = 1 << 40  # a timestamp past the year 36000
ZERO = "0x" + "0" * 40

DRAINER_NOTE = (
    "Signatures like this cost no gas, so wallets often present them as harmless, but they are the most "
    "common way wallet drainers take tokens. Only sign if you started this on a site you trust."
)
CALL_NOTE = "Check it on a block explorer and make sure it is the contract you meant to approve."


@dataclass
class Finding:
    level: str  # danger, warning, note
    text: str


@dataclass
class Report:
    title: str
    fields: list[tuple[str, str]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    hashes: list[tuple[str, str]] = field(default_factory=list)

    def add(self, key: str, value) -> None:
        self.fields.append((key, str(value)))

    def danger(self, text: str) -> None:
        self.findings.append(Finding("danger", text))

    def warn(self, text: str) -> None:
        self.findings.append(Finding("warning", text))

    def note(self, text: str) -> None:
        self.findings.append(Finding("note", text))

    @property
    def worst(self) -> str | None:
        for level in ("danger", "warning", "note"):
            if any(f.level == level for f in self.findings):
                return level
        return None

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "fields": [{"name": k, "value": v} for k, v in self.fields],
            "findings": [{"level": f.level, "text": f.text} for f in self.findings],
            "hashes": dict(self.hashes),
        }


class Context:
    def __init__(self, chain: int | None, now: float | None):
        self.chain = chain
        self.now = int(time.time() if now is None else now)
        self.bare = False  # only calldata given: the target contract is unknown
        self.sender: str | None = None  # the account sending the transaction, when the request says

    def addr(self, value) -> str:
        a = checksum(value)
        name = known.contract_name(a, self.chain)
        if a == ZERO and self.bare:
            return "the target contract"
        if a == ZERO:
            return f"{a} (zero address)"
        return f"{a} ({name})" if name else a

    def known(self, value) -> bool:
        return known.contract_name(checksum(value), self.chain) is not None

    def amount(self, raw: int, token_address, unlimited: int = 1 << 255) -> str:
        info = known.token(checksum(token_address), self.chain)
        if self.bare and checksum(token_address) == ZERO:
            symbol = "of the target token"
        else:
            symbol = info[0] if info else f"of token {checksum(token_address)}"
        if raw >= unlimited:
            return f"unlimited {symbol}"
        if info:
            return f"{units(raw, info[1])} {symbol}"
        return f"{raw} raw units {symbol}"

    def native(self, raw: int) -> str:
        return f"{units(raw, 18)} {known.native(self.chain)}"

    def when(self, ts: int) -> str:
        if ts >= NEVER:
            return "never"
        try:
            dt = datetime.fromtimestamp(ts, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return f"never ({ts})"
        return f"{dt:%Y-%m-%d %H:%M} UTC ({relative(ts - self.now)})"

    def check_deadline(self, r: Report, ts: int, what: str) -> None:
        if ts and ts < self.now:
            r.note(f"The {what} has already passed, so this signature should not work any more.")
        elif ts >= NEVER:
            r.warn(f"There is no real {what}, so this stays usable forever by whoever holds the signature.")
        elif ts - self.now > YEAR:
            r.warn(f"The {what} is {self.when(ts)}. This stays usable until then by whoever holds the signature.")


def units(raw: int, decimals: int) -> str:
    whole, frac = divmod(raw, 10**decimals)
    frac_s = f"{frac:0{decimals}d}".rstrip("0") if decimals else ""
    return f"{whole:,}" + (f".{frac_s}" if frac_s else "")


def relative(seconds: int) -> str:
    future = seconds >= 0
    s = abs(seconds)
    for size, name in ((YEAR, "year"), (86400, "day"), (3600, "hour"), (60, "minute")):
        if s >= size:
            n = s // size
            text = f"{n} {name}{'s' if n != 1 else ''}"
            break
    else:
        return "now"
    return f"in {text}" if future else f"{text} ago"


# ---------------------------------------------------------------- typed data


def explain_typed_data(obj, ctx: Context) -> Report:
    td = eip712.parse(obj)
    domain, msg, primary = td["domain"], td["message"], td["primaryType"]
    if "chainId" in domain:
        ctx.chain = to_int(domain["chainId"])
    contract = domain.get("verifyingContract")
    fields = {f["name"] for f in td["types"][primary]}

    if fields >= {"owner", "spender", "value", "nonce", "deadline"}:
        r = Report("Token permit (ERC-2612)")
    elif fields >= {"holder", "spender", "nonce", "expiry", "allowed"}:
        r = Report("Token permit (DAI-style)")
    elif primary in ("PermitSingle", "PermitBatch") and "details" in fields:
        r = Report("Permit2 allowance")
    elif "permitted" in fields and primary.startswith(
        ("PermitTransferFrom", "PermitBatchTransferFrom", "PermitWitness", "PermitBatchWitness")
    ):
        r = Report("Permit2 transfer")
    elif primary == "OrderComponents" and {"offer", "consideration"} <= fields:
        r = Report("Seaport order (NFT marketplace listing)")
    elif primary == "SafeTx":
        r = Report("Safe transaction")
    elif primary == "SafeMessage":
        r = Report("Safe message")
    else:
        r = Report(f"Typed data: {primary}")

    r.add("network", known.chain_name(ctx.chain))
    app = str(domain.get("name") or "")
    if domain.get("version") not in (None, ""):
        app = f"{app} (version {domain['version']})".strip()
    if app:
        r.add("app (as stated)", app)
    if contract:
        r.add("contract", ctx.addr(contract))
    else:
        r.note("The request names no verifying contract, so the signature is not tied to one contract.")

    name = str(domain.get("name", ""))
    if name == "Permit2" and (not contract or checksum(contract).lower() != known.PERMIT2):
        r.danger(f"The request calls itself Permit2 but the contract is {contract}, not Permit2's {checksum(known.PERMIT2)}.")
    if name == "Seaport" and (not contract or checksum(contract).lower() not in known.SEAPORT):
        r.warn(f"The request calls itself Seaport but {contract} is not a Seaport version signcheck knows.")

    if r.title.startswith("Token permit (ERC"):
        _erc2612(r, msg, contract, ctx)
    elif r.title.startswith("Token permit (DAI"):
        _dai_permit(r, msg, contract, ctx)
    elif r.title == "Permit2 allowance":
        _permit2_allowance(r, msg, ctx)
    elif r.title == "Permit2 transfer":
        _permit2_transfer(r, msg, primary, td["types"], ctx)
    elif r.title.startswith("Seaport"):
        _seaport(r, msg, ctx)
    elif r.title == "Safe transaction":
        _safe_tx(r, msg, contract, ctx)
    elif r.title == "Safe message":
        r.add("message", _short_text(msg.get("message", "")))
        r.note("A Safe message is signed off-chain by the owners. Check what the app will do with it.")
    else:
        for key, value in _flatten(msg, primary, td["types"], ctx)[:60]:
            r.add(key, value)
        r.note("signcheck does not recognise this message type. Read every field above before signing.")

    domain_hash, message_hash, digest = eip712.hashes(td)
    r.hashes.append(("domain hash", "0x" + domain_hash.hex()))
    if message_hash is not None:
        r.hashes.append(("message hash", "0x" + message_hash.hex()))
    r.hashes.append(("digest (signed)", "0x" + digest.hex()))
    return r


def _spender(r: Report, spender, ctx: Context, unlimited: bool, note: str = DRAINER_NOTE, prefix: str = "") -> None:
    if not ctx.known(spender):
        r.warn(f"{prefix}{checksum(spender)} is not a contract signcheck recognises. {note}")
    if unlimited:
        r.warn(f"{prefix}Unlimited: {checksum(spender)} can take all of this token you hold, now and later, until you revoke it.")


def _erc2612(r: Report, msg: dict, contract, ctx: Context) -> None:
    value = to_int(msg["value"])
    deadline = to_int(msg["deadline"])
    r.add("owner", ctx.addr(msg["owner"]))
    r.add("spender", ctx.addr(msg["spender"]))
    r.add("amount", ctx.amount(value, contract or ZERO))
    r.add("deadline", ctx.when(deadline))
    r.add("in short", f"{checksum(msg['spender'])} may spend {ctx.amount(value, contract or ZERO)} from your wallet without asking again.")
    _spender(r, msg["spender"], ctx, value >= 1 << 255)
    ctx.check_deadline(r, deadline, "deadline")


def _dai_permit(r: Report, msg: dict, contract, ctx: Context) -> None:
    allowed = str(msg["allowed"]).lower() in ("true", "1")
    expiry = to_int(msg["expiry"])
    r.add("holder", ctx.addr(msg["holder"]))
    r.add("spender", ctx.addr(msg["spender"]))
    r.add("allowed", "yes, unlimited" if allowed else "no (removes the allowance)")
    r.add("expiry", "none" if expiry == 0 else ctx.when(expiry))
    if allowed:
        _spender(r, msg["spender"], ctx, True)
        if expiry == 0:
            r.warn("The expiry is 0, which DAI-style permits treat as never expiring.")
        else:
            ctx.check_deadline(r, expiry, "expiry")


def _items(value) -> list:
    return value if isinstance(value, list) else [value]


def _permit2_allowance(r: Report, msg: dict, ctx: Context) -> None:
    spender = msg["spender"]
    r.add("spender", ctx.addr(spender))
    unlimited = False
    for i, d in enumerate(_items(msg["details"]), 1):
        amount = to_int(d["amount"])
        unlimited |= amount >= 1 << 159
        tag = f"token {i}" if isinstance(msg["details"], list) else "token"
        r.add(tag, f"{ctx.amount(amount, d['token'], 1 << 159)}, allowance until {ctx.when(to_int(d['expiration']))}")
        ctx.check_deadline(r, to_int(d["expiration"]), f"allowance expiry for {checksum(d['token'])}")
    sig_deadline = to_int(msg["sigDeadline"])
    r.add("signature valid until", ctx.when(sig_deadline))
    r.add("in short", f"{checksum(spender)} may move these tokens through Permit2 until the allowance expires.")
    _spender(r, spender, ctx, unlimited)
    ctx.check_deadline(r, sig_deadline, "signature deadline")


def _permit2_transfer(r: Report, msg: dict, primary: str, types: dict, ctx: Context) -> None:
    spender = msg["spender"]
    r.add("spender", ctx.addr(spender))
    unlimited = False
    for i, p in enumerate(_items(msg["permitted"]), 1):
        amount = to_int(p["amount"])
        unlimited |= amount >= 1 << 255
        r.add(f"token {i}" if isinstance(msg["permitted"], list) else "token", ctx.amount(amount, p["token"]))
    deadline = to_int(msg["deadline"])
    r.add("deadline", ctx.when(deadline))
    r.add("in short", f"{checksum(spender)} may transfer these tokens from you once, before the deadline.")
    extra = [f["name"] for f in types[primary] if f["name"] not in ("permitted", "spender", "nonce", "deadline")]
    if extra:
        r.note(f"It also signs app-specific data ({', '.join(extra)}). Check that it matches what the app showed you.")
    _spender(r, spender, ctx, unlimited)
    ctx.check_deadline(r, deadline, "deadline")


SEAPORT_ITEMS = {0: "native", 1: "ERC-20", 2: "ERC-721", 3: "ERC-1155", 4: "ERC-721 criteria", 5: "ERC-1155 criteria"}


def _seaport_item(item: dict, ctx: Context) -> str:
    kind = to_int(item["itemType"])
    start, end = to_int(item["startAmount"]), to_int(item["endAmount"])
    ident = to_int(item["identifierOrCriteria"])
    token = item["token"]

    def amt(n):
        return ctx.native(n) if kind == 0 else ctx.amount(n, token)

    if kind in (0, 1):
        return amt(start) if start == end else f"{amt(start)} falling/rising to {amt(end)}"
    count = f"{start} x " if kind in (3, 5) else ""
    if kind == 2:
        return f"NFT #{ident} of {ctx.addr(token)}"
    if kind == 3:
        return f"{count}token #{ident} of {ctx.addr(token)}"
    if ident == 0:
        return f"{count}ANY token of {ctx.addr(token)}"
    return f"{count}a token of {ctx.addr(token)} matching criteria 0x{ident:064x}"


def _seaport(r: Report, msg: dict, ctx: Context) -> None:
    offerer = checksum(msg["offerer"])
    r.add("offerer (you)", ctx.addr(offerer))
    offer = msg.get("offer") or []
    gets, others = [], []
    for item in msg.get("consideration") or []:
        (gets if checksum(item["recipient"]) == offerer else others).append(item)
    for item in offer:
        r.add("you give", _seaport_item(item, ctx))
    for item in gets:
        r.add("you receive", _seaport_item(item, ctx))
    if not gets:
        r.add("you receive", "nothing")
    for item in others:
        r.add("also paid", f"{_seaport_item(item, ctx)} to {ctx.addr(item['recipient'])}")
    r.add("valid", f"from {ctx.when(to_int(msg['startTime']))} to {ctx.when(to_int(msg['endTime']))}")
    if offer and not gets:
        r.danger(
            "You get nothing back for what you give. Fake 'login', 'claim' or 'verify' requests that are really "
            "Seaport listings like this are a common way NFTs are stolen."
        )
    if any(to_int(i["itemType"]) in (4, 5) and to_int(i["identifierOrCriteria"]) == 0 for i in offer):
        r.warn("The offer covers ANY token of a collection, not one specific item.")
    ctx.check_deadline(r, to_int(msg["endTime"]), "end time")


SAFE_SETTINGS = {
    "addOwnerWithThreshold": "adds owner {owner} and sets the threshold to {threshold}",
    "removeOwner": "removes owner {owner} and sets the threshold to {threshold}",
    "swapOwner": "replaces owner {oldOwner} with {newOwner}",
    "changeThreshold": "sets the threshold to {threshold}",
    "enableModule": "enables module {module}",
    "disableModule": "disables module {module}",
    "setGuard": "sets the transaction guard to {guard}",
    "setFallbackHandler": "sets the fallback handler to {handler}",
    "changeMasterCopy": "changes the Safe's implementation to {masterCopy}",
}


def _safe_tx(r: Report, msg: dict, safe, ctx: Context) -> None:
    to = checksum(msg["to"])
    value = to_int(msg["value"])
    op = to_int(msg["operation"])
    data = to_bytes(msg["data"]) if msg.get("data") not in (None, "", "0x") else b""
    r.add("to", ctx.addr(to))
    r.add("value", ctx.native(value))
    r.add("operation", "delegatecall (1)" if op == 1 else "call (0)")
    r.add("nonce", to_int(msg["nonce"]))
    if op == 1:
        if to.lower() in known.MULTISEND:
            r.note(f"A delegatecall to {known.contract_name(to, ctx.chain)} is how Safe batches calls. Each call is listed below.")
        else:
            r.danger(
                f"delegatecall: {to} runs its code as the Safe itself, so it can change owners or the implementation "
                "and move everything the Safe holds. Bybit lost about $1.5 billion in February 2025 after its signers "
                "approved a delegatecall like this. Only sign if you know exactly what this contract is."
            )
    _call(r, to, value, data, ctx, safe=checksum(safe) if safe else None)
    gas_price = to_int(msg.get("gasPrice", 0))
    refund = msg.get("refundReceiver", ZERO)
    if gas_price and checksum(refund) != ZERO:
        r.warn(f"The Safe pays a gas refund (gas price {gas_price}) to {checksum(refund)}.")


def _call(r: Report, to: str, value: int, data: bytes, ctx: Context, safe: str | None = None, prefix: str = "") -> None:
    """Describe one call: a transaction, a Safe transaction or one call inside a batch."""
    if not data:
        r.add(prefix + "action", f"send {ctx.native(value)}" if value else "empty call")
        return
    try:
        call = abi.decode(data)
    except ValueError as err:
        r.warn(f"{prefix}The calldata looks like {abi.FUNCTIONS[data[:4]].split('(')[0]} but does not decode: {err}.")
        return
    if call is None:
        r.add(prefix + "function", f"unknown (selector 0x{data[:4].hex()})")
        r.warn(
            f"{prefix}signcheck cannot decode selector 0x{data[:4].hex()}. Look it up on openchain.xyz/signatures "
            "or in the contract's verified source before signing."
        )
        return
    a = call.args
    r.add(prefix + "function", call.signature)
    if call.name in ("approve", "increaseAllowance") and "token" not in a:
        amount = a["amount"]
        r.add(prefix + "action", f"lets {ctx.addr(a['spender'])} spend {ctx.amount(amount, to)}")
        _spender(r, a["spender"], ctx, amount >= 1 << 255, CALL_NOTE, prefix)
    elif call.name == "approve":
        r.add(prefix + "action", f"Permit2 allowance: {ctx.addr(a['spender'])} may spend {ctx.amount(a['amount'], a['token'], 1 << 159)}")
        r.add(prefix + "expires", ctx.when(a["expiration"]))
        _spender(r, a["spender"], ctx, a["amount"] >= 1 << 159, CALL_NOTE, prefix)
    elif call.name == "transfer":
        r.add(prefix + "action", f"sends {ctx.amount(a['amount'], to)} to {ctx.addr(a['to'])}")
    elif call.name == "transferFrom":
        r.add(
            prefix + "action",
            f"moves {ctx.amount(a['amount'], to)} (or NFT #{a['amount']}) from {ctx.addr(a['from'])} to {ctx.addr(a['to'])}",
        )
    elif call.name == "safeTransferFrom":
        what = f"{a['amount']} x token #{a['id']}" if "id" in a else f"NFT #{a['tokenId']}"
        r.add(prefix + "action", f"sends {what} of {ctx.addr(to)} from {ctx.addr(a['from'])} to {ctx.addr(a['to'])}")
    elif call.name == "setApprovalForAll":
        if a["approved"]:
            r.add(prefix + "action", f"lets {ctx.addr(a['operator'])} move every token you own in {ctx.addr(to)}")
            r.warn(f"{prefix}{checksum(a['operator'])} gets control of your whole collection at {to}, including tokens you get later.")
            if not ctx.known(a["operator"]):
                r.warn(f"{prefix}{checksum(a['operator'])} is not a contract signcheck recognises. {CALL_NOTE}")
        else:
            r.add(prefix + "action", f"revokes {ctx.addr(a['operator'])}'s access to {ctx.addr(to)}")
    elif call.name == "multiSend":
        try:
            calls = abi.multisend(a["transactions"])
        except ValueError as err:
            r.warn(f"{prefix}The multiSend batch does not decode: {err}.")
            return
        r.add(prefix + "batch", f"{len(calls)} calls")
        for i, (op, sub_to, sub_value, sub_data) in enumerate(calls, 1):
            p = f"{prefix}call {i}: "
            r.add(p + "to", f"{ctx.addr(sub_to)}{' via delegatecall' if op == 1 else ''}")
            if op == 1:
                r.danger(f"{p}delegatecall to {sub_to} runs its code as the Safe and can take full control of it.")
            if sub_value:
                r.add(p + "value", ctx.native(sub_value))
            _call(r, sub_to, sub_value, sub_data, ctx, safe, p)
    elif call.name == "execute":
        router.explain_execute(r, a, to, ctx, prefix, safe or ctx.sender)
    elif call.name in SAFE_SETTINGS:
        text = SAFE_SETTINGS[call.name].format(**{k: (checksum(v) if isinstance(v, str) else v) for k, v in a.items()})
        r.add(prefix + "action", text)
        if safe is not None and to != safe:
            r.note(f"{prefix}This Safe settings call goes to {to}, not to the Safe that signs it.")
        elif call.name in ("enableModule", "changeMasterCopy") or (call.name == "setGuard" and not ctx.known(a["guard"])):
            r.danger(f"{prefix}This {text}. A module or implementation can move the Safe's funds without the owners' signatures.")
        elif a.get("threshold") == 1:
            r.danger(f"{prefix}This {text}, so a single owner can then move everything the Safe holds.")
        else:
            r.warn(f"{prefix}This changes who controls the Safe: it {text}.")
    if value:
        r.add(prefix + "value", ctx.native(value))


def _flatten(value, t: str, types: dict, ctx: Context, path: str = "") -> list[tuple[str, str]]:
    if t in types and isinstance(value, dict):
        out = []
        for f in types[t]:
            out += _flatten(value.get(f["name"]), f["type"], types, ctx, f"{path}.{f['name']}" if path else f["name"])
        return out
    if t.endswith("]") and isinstance(value, list):
        base = t[: t.rindex("[")]
        out = []
        for i, v in enumerate(value):
            out += _flatten(v, base, types, ctx, f"{path}[{i}]")
        return out or [(path, "[]")]
    if t == "address":
        try:
            return [(path, ctx.addr(value))]
        except TypedDataError:
            pass
    return [(path, _short_text(value))]


def _short_text(value, limit: int = 200) -> str:
    s = value if isinstance(value, str) else json.dumps(value)
    return s if len(s) <= limit else s[:limit] + f"... ({len(s)} characters)"


# ---------------------------------------------------------------- messages and transactions


def explain_personal_sign(message, ctx: Context) -> Report:
    raw = to_bytes(message) if isinstance(message, str) and re.fullmatch(r"0x[0-9a-fA-F]*", message) else str(message).encode()
    try:
        text = raw.decode("utf-8")
        printable = all(c.isprintable() or c in "\r\n\t" for c in text)
    except UnicodeDecodeError:
        text, printable = None, False
    siwe = printable and "wants you to sign in with your Ethereum account" in text
    r = Report("Sign-in with Ethereum (EIP-4361)" if siwe else "Message signature (personal_sign)")
    if printable:
        lines = text.splitlines() or [""]
        for i, line in enumerate(lines[:30]):
            r.add("message" if i == 0 else "", line)
        if len(lines) > 30:
            r.add("", f"... {len(lines) - 30} more lines")
    else:
        r.add("message (hex)", "0x" + raw.hex())
    if siwe:
        site = text.split(" wants you", 1)[0].strip()
        r.add("site", site)
        r.note(f"Check that you are on {site} yourself. A sign-in proves you own the address and moves nothing.")
    elif not printable and len(raw) == 32:
        r.warn("This is a bare 32-byte hash, so you cannot see what it stands for. Ask the app what it is before signing.")
    elif not printable:
        r.warn("The message is not readable text. Ask the app what it is before signing.")
    else:
        r.note("A plain message signature cannot move funds by itself on Ethereum, but check why the site wants it.")
    prefix = f"\x19Ethereum Signed Message:\n{len(raw)}".encode()
    r.hashes.append(("digest (signed)", "0x" + keccak256(prefix + raw).hex()))
    return r


def explain_eth_sign(data, ctx: Context) -> Report:
    r = Report("Raw hash signature (eth_sign)")
    r.add("hash", data)
    r.danger(
        "eth_sign signs any 32-byte hash, which can be a transaction or permit you cannot see. Wallets such as "
        "MetaMask turn it off by default. Do not sign this unless you computed the hash yourself."
    )
    return r


def explain_transaction(tx: dict, ctx: Context) -> Report:
    if "chainId" in tx:
        ctx.chain = to_int(tx["chainId"])
    data_hex = tx.get("data") or tx.get("input") or "0x"
    data = to_bytes(data_hex) if data_hex != "0x" else b""
    value = to_int(tx.get("value", 0))
    to = tx.get("to")
    r = Report("Transaction")
    r.add("network", known.chain_name(ctx.chain))
    if tx.get("from"):
        r.add("from", ctx.addr(tx["from"]))
        ctx.sender = checksum(tx["from"])
    _authorizations(r, tx.get("authorizationList") or [], ctx)
    if not to:
        r.add("to", "none: this deploys a new contract")
        r.add("value", ctx.native(value))
        r.note("Contract deployments cannot be decoded. Make sure you meant to deploy a contract.")
        return r
    r.add("to", ctx.addr(to))
    _call(r, checksum(to), value, data, ctx)
    return r


def _rlp(payload: bytes, offset: int = 0x80) -> bytes:
    if offset == 0x80 and len(payload) == 1 and payload[0] < 0x80:
        return payload
    if len(payload) < 56:
        return bytes([offset + len(payload)]) + payload
    size = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(size)]) + size + payload


def _authorization_hash(chain: int, target: str, nonce: int) -> bytes:
    """The EIP-7702 digest: keccak256(0x05 || rlp([chain_id, address, nonce]))."""
    chain_bytes, nonce_bytes = (n.to_bytes((n.bit_length() + 7) // 8, "big") for n in (chain, nonce))
    return keccak256(b"\x05" + _rlp(_rlp(chain_bytes) + _rlp(bytes.fromhex(target[2:])) + _rlp(nonce_bytes), 0xC0))


def _authorizations(r: Report, items: list, ctx: Context) -> None:
    """EIP-7702: each entry makes the signer's account run the code at another address."""
    for i, auth in enumerate(items, 1):
        name = f"authorization {i}"
        target = auth.get("address") or auth.get("contractAddress")
        if not target:
            raise TypedDataError(f"{name}: no address")
        target = checksum(target)
        chain = to_int(auth.get("chainId", 0))
        where = "every chain" if chain == 0 else known.chain_name(chain)
        if target == checksum(ZERO):
            r.add(name, f"removes the delegation from your account on {where}")
            r.note(f"{name}: this clears an earlier delegation, so your account goes back to being a plain wallet.")
        else:
            r.add(name, f"makes your account run the code at {ctx.addr(target)} on {where}")
            r.danger(
                f"{name}: the code at {target} would run as your own account on {where}, and it can move everything you "
                "hold without asking again until the delegation is replaced. Only sign if your wallet itself offered "
                "this upgrade."
            )
        if "nonce" in auth:
            r.hashes.append((f"{name} hash", "0x" + _authorization_hash(chain, target, to_int(auth["nonce"])).hex()))


def explain_calls(params: dict, ctx: Context) -> Report:
    """wallet_sendCalls (EIP-5792): a batch of calls."""
    if "chainId" in params:
        ctx.chain = to_int(params["chainId"])
    calls = params.get("calls") or []
    r = Report(f"Batch of {len(calls)} calls (wallet_sendCalls)")
    r.add("network", known.chain_name(ctx.chain))
    if params.get("from"):
        ctx.sender = checksum(params["from"])
    for i, c in enumerate(calls, 1):
        p = f"call {i}: "
        data = c.get("data") or "0x"
        value = to_int(c.get("value", 0))
        if not c.get("to"):
            r.add(p + "to", "none: deploys a contract")
            continue
        r.add(p + "to", ctx.addr(c["to"]))
        _call(r, checksum(c["to"]), value, to_bytes(data) if data != "0x" else b"", ctx, prefix=p)
    return r


def _is_address(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", value) is not None


def explain(request, chain: int | None = None, now: float | None = None) -> Report:
    """Explain any supported request: JSON-RPC call, typed data, transaction, or bare calldata."""
    ctx = Context(chain, now)
    if isinstance(request, str):
        s = request.strip()
        if s.startswith(("{", "[")):
            try:
                request = json.loads(s)
            except json.JSONDecodeError as err:
                raise TypedDataError(f"not valid JSON: {err}") from None
        elif re.fullmatch(r"0x[0-9a-fA-F]{8,}", s):
            return _bare_calldata(s, ctx)
        else:
            raise TypedDataError("input is neither JSON nor 0x-prefixed calldata")
    if not isinstance(request, dict):
        raise TypedDataError("expected a JSON object")

    method = request.get("method")
    if method is not None:
        params = request.get("params") or []
        if method in ("eth_signTypedData_v4", "eth_signTypedData_v3", "eth_signTypedData"):
            typed = next((p for p in params if isinstance(p, dict) or (isinstance(p, str) and p.lstrip().startswith("{"))), None)
            if typed is None:
                raise TypedDataError(f"{method}: no typed data in params (the legacy v1 array format is not supported)")
            return explain_typed_data(typed, ctx)
        if method == "personal_sign":
            if not params:
                raise TypedDataError("personal_sign: no params")
            message = params[1] if len(params) > 1 and _is_address(params[0]) and not _is_address(params[1]) else params[0]
            return explain_personal_sign(message, ctx)
        if method == "eth_sign":
            return explain_eth_sign(params[-1] if params else "", ctx)
        if method in ("eth_sendTransaction", "eth_signTransaction"):
            return explain_transaction(params[0], ctx)
        if method == "wallet_sendCalls":
            return explain_calls(params[0], ctx)
        raise TypedDataError(f"unsupported method {method!r}")
    if {"types", "primaryType"} <= request.keys():
        return explain_typed_data(request, ctx)
    if request.keys() & {"to", "data", "input", "authorizationList"}:
        return explain_transaction(request, ctx)
    if "calls" in request:
        return explain_calls(request, ctx)
    raise TypedDataError("unrecognised request: expected typed data, a transaction, or a JSON-RPC call")


def _bare_calldata(data_hex: str, ctx: Context) -> Report:
    ctx.bare = True
    r = Report("Calldata")
    r.add("network", known.chain_name(ctx.chain))
    r.note("Only calldata was given, so the contract it is sent to is unknown. Token amounts are shown in raw units.")
    _call(r, ZERO, 0, to_bytes(data_hex), ctx)
    return r
