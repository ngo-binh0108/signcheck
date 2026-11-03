"""Chains, contracts and tokens signcheck can name. Anything else is shown as a bare address."""

from __future__ import annotations

CHAINS = {
    1: ("Ethereum", "ETH"),
    10: ("OP Mainnet", "ETH"),
    56: ("BNB Smart Chain", "BNB"),
    100: ("Gnosis", "xDAI"),
    137: ("Polygon", "POL"),
    324: ("zkSync Era", "ETH"),
    8453: ("Base", "ETH"),
    42161: ("Arbitrum One", "ETH"),
    43114: ("Avalanche C-Chain", "AVAX"),
    59144: ("Linea", "ETH"),
    534352: ("Scroll", "ETH"),
    11155111: ("Sepolia testnet", "ETH"),
}

ANY = None  # deployed at the same address on every chain it supports

# lower-case address -> (name, chain ids or ANY)
CONTRACTS = {
    "0x000000000022d473030f116ddee9f6b43ac78ba3": ("Uniswap Permit2", ANY),
    "0x00000000000000adc04c56bf30ac9d3c0aaf14dc": ("Seaport 1.5", ANY),
    "0x0000000000000068f116a894984e2db1123eb395": ("Seaport 1.6", ANY),
    "0x111111125421ca6dc452d289314280a0f8842a65": ("1inch Router v6", ANY),
    "0xc92e8bdf79f0507f65a392b0ab4667716bfe0110": ("CoW Protocol vault relayer", ANY),
    "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": ("Uniswap Universal Router", {1}),
    "0x66a9893cc07d91d95644aedd05d03f95e1dba8af": ("Uniswap Universal Router (v4)", {1}),
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": ("Uniswap V2 Router", {1}),
    "0xe592427a0aece92de3edee1f18e0157c05861564": ("Uniswap V3 SwapRouter", {1}),
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": ("Uniswap SwapRouter02", {1}),
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": ("0x Exchange Proxy", {1}),
    "0xa238cbeb142c10ef7ad8442c6d1f9e89e07e7761": ("Safe MultiSend 1.3.0", ANY),
    "0x40a2accbd92bca938b02010e17a5b8929b49130d": ("Safe MultiSendCallOnly 1.3.0", ANY),
    "0x38869bf66a61cf6bdb996a6ae40d5853fd43b526": ("Safe MultiSend 1.4.1", ANY),
    "0x9641d764fc13c8b624c04430c7356c1c7c8102e2": ("Safe MultiSendCallOnly 1.4.1", ANY),
}

PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"
SEAPORT = {a for a, (name, _) in CONTRACTS.items() if name.startswith("Seaport")}
MULTISEND = {a for a, (name, _) in CONTRACTS.items() if "MultiSend" in name}

# (chain id, lower-case address) -> (symbol, decimals)
TOKENS = {
    (1, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"): ("USDC", 6),
    (1, "0xdac17f958d2ee523a2206206994597c13d831ec7"): ("USDT", 6),
    (1, "0x6b175474e89094c44da98b954eedeac495271d0f"): ("DAI", 18),
    (1, "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"): ("WETH", 18),
}


def contract_name(address: str, chain: int | None) -> str | None:
    entry = CONTRACTS.get(address.lower())
    if entry and (entry[1] is ANY or chain in entry[1]):
        return entry[0]
    return None


def token(address: str, chain: int | None) -> tuple[str, int] | None:
    return TOKENS.get((chain, address.lower()))


def chain_name(chain: int | None) -> str:
    if chain is None:
        return "not stated"
    name = CHAINS.get(chain, (None,))[0]
    return f"{name} (chain {chain})" if name else f"chain {chain}"


def native(chain: int | None) -> str:
    return CHAINS.get(chain, (None, "native coin"))[1]
