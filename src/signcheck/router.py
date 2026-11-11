"""Explain Uniswap Universal Router calls: execute(bytes commands, bytes[] inputs, uint256 deadline).

Each byte of `commands` is one step, and `inputs` holds its ABI-encoded arguments. A V4_SWAP step holds a
second list of actions (swap, settle what you pay, take what you get) in the same way. Step and action numbers
follow Commands.sol in universal-router and Actions.sol in v4-periphery.

What matters before signing is where the tokens end up: a swap whose output, or a Permit2 transfer whose tokens,
go to an address other than yours is what a malicious front end would send.
"""

from __future__ import annotations

from signcheck import abi, known
from signcheck.eip712 import checksum

MSG_SENDER = checksum(1)  # the router's stand-ins for "the caller" and "the router itself"
ADDRESS_THIS = checksum(2)
ZERO = checksum(0)
CONTRACT_BALANCE = 1 << 255
ALLOW_REVERT = 0x80
COMMAND_MASK = 0x3F
DYNAMIC_FEE = 0x800000  # v4 pools whose hook sets the fee per swap
V1_ROUTER = "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad"  # its commands 0x10 to 0x1d are NFT markets

PERMIT_SINGLE = "((address,uint160,uint48,uint48),address,uint256)"
POOL_KEY = "(address,address,uint24,int24,address)"
PATH_KEY = "(address,uint24,int24,address,bytes)"

COMMANDS = {
    0x00: ("V3_SWAP_EXACT_IN", ["address", "uint256", "uint256", "bytes", "bool"]),
    0x01: ("V3_SWAP_EXACT_OUT", ["address", "uint256", "uint256", "bytes", "bool"]),
    0x02: ("PERMIT2_TRANSFER_FROM", ["address", "address", "uint160"]),
    0x03: ("PERMIT2_PERMIT_BATCH", ["((address,uint160,uint48,uint48)[],address,uint256)", "bytes"]),
    0x04: ("SWEEP", ["address", "address", "uint256"]),
    0x05: ("TRANSFER", ["address", "address", "uint256"]),
    0x06: ("PAY_PORTION", ["address", "address", "uint256"]),
    0x08: ("V2_SWAP_EXACT_IN", ["address", "uint256", "uint256", "address[]", "bool"]),
    0x09: ("V2_SWAP_EXACT_OUT", ["address", "uint256", "uint256", "address[]", "bool"]),
    0x0A: ("PERMIT2_PERMIT", [PERMIT_SINGLE, "bytes"]),
    0x0B: ("WRAP_ETH", ["address", "uint256"]),
    0x0C: ("UNWRAP_WETH", ["address", "uint256"]),
    0x0D: ("PERMIT2_TRANSFER_FROM_BATCH", ["(address,address,uint160,address)[]"]),
    0x0E: ("BALANCE_CHECK_ERC20", ["address", "address", "uint256"]),
    0x10: ("V4_SWAP", ["bytes", "bytes[]"]),
    0x11: ("V3_POSITION_MANAGER_PERMIT", None),
    0x12: ("V3_POSITION_MANAGER_CALL", None),
    0x13: ("V4_INITIALIZE_POOL", None),
    0x14: ("V4_POSITION_MANAGER_CALL", None),
    0x21: ("EXECUTE_SUB_PLAN", ["bytes", "bytes[]"]),
}

ACTIONS = {
    0x06: ("SWAP_EXACT_IN_SINGLE", [f"({POOL_KEY},bool,uint128,uint128,bytes)"]),
    0x07: ("SWAP_EXACT_IN", [f"(address,{PATH_KEY}[],uint128,uint128)"]),
    0x08: ("SWAP_EXACT_OUT_SINGLE", [f"({POOL_KEY},bool,uint128,uint128,bytes)"]),
    0x09: ("SWAP_EXACT_OUT", [f"(address,{PATH_KEY}[],uint128,uint128)"]),
    0x0B: ("SETTLE", ["address", "uint256", "bool"]),
    0x0C: ("SETTLE_ALL", ["address", "uint256"]),
    0x0D: ("SETTLE_PAIR", ["address", "address"]),
    0x0E: ("TAKE", ["address", "address", "uint256"]),
    0x0F: ("TAKE_ALL", ["address", "uint256"]),
    0x10: ("TAKE_PORTION", ["address", "address", "uint256"]),
    0x11: ("TAKE_PAIR", ["address", "address", "address"]),
    0x12: ("CLOSE_CURRENCY", ["address"]),
    0x13: ("CLEAR_OR_TAKE", ["address", "uint256"]),
    0x14: ("SWEEP", ["address", "address"]),
    0x15: ("WRAP", ["uint256"]),
    0x16: ("UNWRAP", ["uint256"]),
}


class _Steps:
    """Report fields and findings for one execute() call, with each problem address reported once."""

    def __init__(self, r, ctx, router: str, prefix: str, sender: str | None):
        self.r, self.ctx, self.router, self.prefix = r, ctx, checksum(router), prefix
        self.sender = checksum(sender) if sender else None
        self.warned: set[str] = set()

    def mine(self, a: str) -> bool:
        return a in (MSG_SENDER, ADDRESS_THIS, self.router) or a == self.sender

    def who(self, a: str) -> str:
        if a == MSG_SENDER:
            return "you (the sender)"
        if a == ADDRESS_THIS:
            return "the router, for a later step"
        if a == self.router:
            return "the router"
        if a == self.sender:
            return f"you ({a})"
        return self.ctx.addr(a)

    def money(self, raw: int, token: str, at_least: bool = False) -> str:
        if raw == CONTRACT_BALANCE:
            return f"the router's whole balance of {self.symbol(token)}"
        if token == ZERO:
            text = self.ctx.native(raw)
        else:
            text = self.ctx.amount(raw, token, 1 << 256)
        return f"at least {text}" if at_least else text

    def symbol(self, token: str) -> str:
        if token == ZERO:
            return known.native(self.ctx.chain)
        info = known.token(token, self.ctx.chain)
        return info[0] if info else f"token {token}"

    def receives(self, a: str, what: str) -> None:
        """`a` is sent `what`: warn once if that is not the sender."""
        if self.mine(a) or a in self.warned:
            return
        self.warned.add(a)
        if self.sender is not None:
            self.r.warn(f"{self.prefix}{a} receives {what}, and it is not the address sending this transaction.")
        else:
            self.r.note(f"{self.prefix}{what[0].upper() + what[1:]} goes to {a}. Make sure that is your address.")


def explain_execute(r, args: dict, router: str, ctx, prefix: str = "", sender: str | None = None) -> None:
    """Add the steps of a Universal Router execute() call to the report.

    `sender` is the address calling the router (the wallet, or the Safe), when it is known.
    """
    s = _Steps(r, ctx, router, prefix, sender)
    r.add(prefix + "steps", f"{len(args['commands'])} (Uniswap Universal Router)")
    _commands(s, args["commands"], args["inputs"], prefix)
    if "deadline" in args:
        r.add(prefix + "deadline", ctx.when(args["deadline"]))
        if args["deadline"] < ctx.now:
            r.note(f"{prefix}The deadline has passed, so the router will reject this transaction.")


def _commands(s: _Steps, commands: bytes, inputs: list, prefix: str) -> None:
    if len(commands) != len(inputs):
        s.r.warn(f"{prefix}The router call has {len(commands)} commands but {len(inputs)} inputs, so it will fail.")
    for i, (byte, data) in enumerate(zip(commands, inputs), 1):
        p = f"{prefix}step {i}: "
        code = byte & COMMAND_MASK
        name, types = COMMANDS.get(code, (None, None))
        if s.router.lower() == V1_ROUTER and 0x10 <= code <= 0x1D:
            name, types = f"NFT market command 0x{code:02x}", None
        if name is None:
            s.r.add(p + "command", f"unknown (0x{code:02x})")
            s.r.warn(f"{p}signcheck does not know router command 0x{code:02x}, so it cannot say what this step does.")
            continue
        if byte & ALLOW_REVERT:
            name += " (allowed to fail)"
        if types is None:
            s.r.add(p + "command", f"{name}, not decoded")
            continue
        try:
            values = abi.decode_values(types, data)
        except ValueError as err:
            s.r.warn(f"{p}The {name} step does not decode: {err}.")
            continue
        _command(s, code, name, values, p)


def _v3_path(path: bytes) -> list[str]:
    """Tokens of a packed V3 path: token (20 bytes), then fee (3) and token (20) per hop."""
    if len(path) < 43 or (len(path) - 20) % 23:
        raise ValueError("the V3 path is malformed")
    return [checksum(int.from_bytes(path[i : i + 20], "big")) for i in range(0, len(path), 23)]


def _command(s: _Steps, code: int, name: str, v: list, p: str) -> None:
    r = s.r
    if code in (0x00, 0x01, 0x08, 0x09):
        recipient, amount, limit, path = v[0], v[1], v[2], v[3]
        try:
            tokens = _v3_path(path) if code <= 0x01 else path
        except ValueError as err:
            r.warn(f"{p}The {name} step does not decode: {err}.")
            return
        if len(tokens) < 2:
            r.warn(f"{p}The {name} step has a path with fewer than two tokens.")
            return
        if code == 0x01:  # V3 exact-output paths run from the output token back to the input
            tokens = tokens[::-1]
        pay, get = tokens[0], tokens[-1]
        pool = "Uniswap v3" if code <= 0x01 else "Uniswap v2"
        if code in (0x00, 0x08):
            r.add(p + "swap", f"{s.money(amount, pay)} for {s.money(limit, get, True)} on {pool}, to {s.who(recipient)}")
            if limit == 0:
                r.warn(f"{p}The swap accepts any amount out, even nothing, so a sandwich bot can take almost all of it.")
        else:
            r.add(p + "swap", f"at most {s.money(limit, pay)} for {s.money(amount, get)} on {pool}, to {s.who(recipient)}")
        s.receives(recipient, f"the {s.symbol(get)} from this swap")
    elif code == 0x02:
        token, recipient, amount = v
        r.add(p + "permit2 transfer", f"{s.money(amount, token)} from you to {s.who(recipient)}")
        s.receives(recipient, f"{s.money(amount, token)} taken from your wallet through Permit2")
    elif code in (0x03, 0x0A):
        permit, _signature = v
        details = permit[0] if code == 0x03 else [permit[0]]
        spender = permit[1]
        for token, amount, expiration, _nonce in details:
            r.add(
                p + "permit2 allowance",
                f"{s.who(spender)} may spend {s.money(amount, token) if amount < (1 << 160) - 1 else 'unlimited ' + s.symbol(token)}"
                f" until {s.ctx.when(expiration)}",
            )
        if spender != s.router:
            r.danger(
                f"{p}This signs a Permit2 allowance for {spender}, not for the router being called. Whoever controls "
                "that address can take the tokens later."
            )
    elif code in (0x04, 0x05):
        token, recipient, amount = v
        verb = "sweep" if code == 0x04 else "transfer"
        what = s.money(amount, token, at_least=code == 0x04)
        if code == 0x04 and amount == 0:
            what = f"all {s.symbol(token)} left in the router"
        r.add(p + verb, f"{what} to {s.who(recipient)}")
        s.receives(recipient, what if code == 0x05 else f"the {s.symbol(token)} left in the router")
    elif code == 0x06:
        token, recipient, bips = v
        _portion(s, p, token, recipient, bips)
    elif code in (0x0B, 0x0C):
        recipient, amount = v
        verb, what = ("wrap", "ETH into WETH") if code == 0x0B else ("unwrap", "WETH into ETH")
        r.add(p + verb, f"{what}, to {s.who(recipient)}")
        s.receives(recipient, "the " + what.split()[-1])
    elif code == 0x0D:
        for owner, recipient, amount, token in v[0]:
            r.add(p + "permit2 transfer", f"{s.money(amount, token)} from {s.who(owner)} to {s.who(recipient)}")
            s.receives(recipient, f"{s.money(amount, token)} taken through Permit2")
    elif code == 0x0E:
        owner, token, minimum = v
        r.add(p + "check", f"{s.who(owner)} holds {s.money(minimum, token, True)}, or the whole call fails")
    elif code == 0x10:
        actions, params = v
        _v4(s, actions, params, p)
    elif code == 0x21:
        r.add(p + "sub-plan", f"{len(v[0])} steps")
        _commands(s, v[0], v[1], p + "sub-plan ")


def _portion(s: _Steps, p: str, token: str, recipient: str, bips: int) -> None:
    s.r.add(p + "fee", f"{bips / 100:g}% of the {s.symbol(token)} to {s.who(recipient)}")
    if bips > 100 and not s.mine(recipient):
        s.r.warn(f"{p}{recipient} takes {bips / 100:g}% of your {s.symbol(token)} as a fee. Most front ends charge 1% or less.")


def _v4(s: _Steps, actions: bytes, params: list, prefix: str) -> None:
    r = s.r
    s.unprotected, s.minimum = [], False
    if len(actions) != len(params):
        r.warn(f"{prefix}The v4 swap has {len(actions)} actions but {len(params)} parameters, so it will fail.")
    for j, (code, data) in enumerate(zip(actions, params), 1):
        p = f"{prefix}v4 action {j}: "
        name, types = ACTIONS.get(code, (None, None))
        if name is None:
            r.add(p + "action", f"0x{code:02x}, not decoded")
            continue
        try:
            v = abi.decode_values(types, data)
        except ValueError as err:
            r.warn(f"{p}The {name} action does not decode: {err}.")
            continue
        if code in (0x06, 0x08):
            (c0, c1, fee, _spacing, hooks), zero_for_one, amount, limit, _hook_data = v[0]
            pay, get = (c0, c1) if zero_for_one else (c1, c0)
            _v4_swap(s, p, code == 0x06, pay, get, amount, limit, [hooks], [fee])
        elif code in (0x07, 0x09):
            start, path, amount, limit = v[0]
            tokens = [start] + [hop[0] for hop in path]
            if code == 0x09:  # exact output: the path runs from the output token back
                tokens = tokens[::-1]
            if len(tokens) < 2:
                r.warn(f"{p}The {name} action has an empty path.")
                continue
            _v4_swap(s, p, code == 0x07, tokens[0], tokens[-1], amount, limit, [hop[3] for hop in path], [hop[1] for hop in path])
        elif code == 0x0B:
            currency, amount, payer_is_user = v
            what = f"all the {s.symbol(currency)} the swap needs" if amount == 0 else s.money(amount, currency)
            r.add(p + "pay", f"{what}, from {'you' if payer_is_user else 'the router'}")
        elif code == 0x0C:
            currency, maximum = v
            r.add(p + "pay", f"up to {s.money(maximum, currency)}, from you")
        elif code == 0x0E:
            currency, recipient, amount = v
            what = f"all the {s.symbol(currency)} from the swap" if amount == 0 else s.money(amount, currency)
            r.add(p + "receive", f"{what}, to {s.who(recipient)}")
            s.receives(recipient, what)
        elif code == 0x0F:
            currency, minimum = v
            least = f" ({s.money(minimum, currency, True)})" if minimum else ""
            r.add(p + "receive", f"the {s.symbol(currency)} from the swap{least}, to you")
            s.minimum |= minimum > 0
        elif code == 0x10:
            currency, recipient, bips = v
            _portion(s, p, currency, recipient, bips)
        elif code == 0x11:
            c0, c1, recipient = v
            r.add(p + "receive", f"the {s.symbol(c0)} and {s.symbol(c1)} owed, to {s.who(recipient)}")
            s.receives(recipient, f"the {s.symbol(c0)} and {s.symbol(c1)} from this swap")
        elif code == 0x14:
            currency, recipient = v
            r.add(p + "sweep", f"the {s.symbol(currency)} left over, to {s.who(recipient)}")
            s.receives(recipient, f"the {s.symbol(currency)} left over")
        else:
            r.add(p + "action", name.lower().replace("_", " "))
    if s.unprotected and not s.minimum:
        r.warn(
            f"{s.unprotected[0]}The swap accepts any amount out, even nothing, and no later action sets a minimum, "
            "so a sandwich bot can take almost all of it."
        )


def _v4_swap(s: _Steps, p: str, exact_in: bool, pay: str, get: str, amount: int, limit: int, hooks: list, fees: list) -> None:
    if len(fees) != 1:
        pool = f"Uniswap v4, {len(fees)} pools"
    elif fees[0] & DYNAMIC_FEE:
        pool = "Uniswap v4, dynamic fee"
    else:
        pool = f"Uniswap v4, fee {fees[0] / 10000:g}%"
    if exact_in:
        s.r.add(p + "swap", f"{s.money(amount, pay)} for {s.money(limit, get, True)} ({pool})")
        if limit == 0:
            s.unprotected.append(p)
        else:
            s.minimum = True
    else:
        s.r.add(p + "swap", f"at most {s.money(limit, pay)} for {s.money(amount, get)} ({pool})")
    custom = sorted({h for h in hooks if h != ZERO})
    if custom:
        s.r.note(f"{p}The pool runs hook contract {', '.join(custom)}, which can add its own fees or logic to the swap.")
