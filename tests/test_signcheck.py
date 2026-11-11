import json
import os
from pathlib import Path

import pytest

from signcheck import abi, eip712, known
from signcheck.cli import main
from signcheck.explain import explain
from signcheck.keccak import keccak256

EXAMPLES = Path(__file__).parent.parent / "examples"
NOW = 1793700000  # 2026-11-03
ALICE = "0x1234567890AbcdEF1234567890aBcdef12345678"
BAD = "0xbAd00000000000000000000000000000000000Ad"
USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
MAX = 2**256 - 1

MAIL = {
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ],
        "Person": [{"name": "name", "type": "string"}, {"name": "wallet", "type": "address"}],
        "Mail": [{"name": "from", "type": "Person"}, {"name": "to", "type": "Person"}, {"name": "contents", "type": "string"}],
    },
    "primaryType": "Mail",
    "domain": {"name": "Ether Mail", "version": "1", "chainId": 1, "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},
    "message": {
        "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
        "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
        "contents": "Hello, Bob!",
    },
}


def levels(report):
    return [f.level for f in report.findings]


def text(report):
    return "\n".join(f"{k} {v}" for k, v in report.fields) + "\n" + "\n".join(f.text for f in report.findings)


def permit(spender=BAD, value=MAX, deadline=NOW + 3600):
    return {
        "types": {
            "Permit": [
                {"name": "owner", "type": "address"},
                {"name": "spender", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"},
            ]
        },
        "primaryType": "Permit",
        "domain": {"name": "USD Coin", "version": "2", "chainId": 1, "verifyingContract": USDC},
        "message": {"owner": ALICE, "spender": spender, "value": str(value), "nonce": 0, "deadline": deadline},
    }


def permit2_single(amount, expiration, spender, contract=PERMIT2):
    return {
        "types": {
            "PermitSingle": [
                {"name": "details", "type": "PermitDetails"},
                {"name": "spender", "type": "address"},
                {"name": "sigDeadline", "type": "uint256"},
            ],
            "PermitDetails": [
                {"name": "token", "type": "address"},
                {"name": "amount", "type": "uint160"},
                {"name": "expiration", "type": "uint48"},
                {"name": "nonce", "type": "uint48"},
            ],
        },
        "primaryType": "PermitSingle",
        "domain": {"name": "Permit2", "chainId": 1, "verifyingContract": contract},
        "message": {
            "details": {"token": USDC, "amount": str(amount), "expiration": expiration, "nonce": 0},
            "spender": spender,
            "sigDeadline": NOW + 1800,
        },
    }


# ---------------------------------------------------------------- hashing


def test_keccak_vectors():
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert keccak256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"


def test_keccak_matches_pycryptodome_across_block_boundaries():
    keccak = pytest.importorskip("Crypto.Hash.keccak")
    for n in [*range(0, 300), 1000, 4096]:
        data = os.urandom(n)
        assert keccak256(data) == keccak.new(data=data, digest_bits=256).digest(), n


def test_checksum_eip55_vectors():
    for a in [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    ]:
        assert eip712.checksum(a.lower()) == a


def test_selectors():
    assert abi.selector("approve(address,uint256)").hex() == "095ea7b3"
    assert abi.selector("transfer(address to,uint256 amount)").hex() == "a9059cbb"
    assert abi.selector("transferFrom(address,address,uint256)").hex() == "23b872dd"
    assert abi.selector("setApprovalForAll(address,bool)").hex() == "a22cb465"


def test_eip712_spec_example():
    td = eip712.parse(MAIL)
    assert eip712.encode_type("Mail", td["types"]) == "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
    domain, message, digest = eip712.hashes(td)
    assert domain.hex() == "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
    assert message.hex() == "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
    assert digest.hex() == "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"


def typed_examples():
    yield MAIL
    yield permit()
    yield permit2_single(MAX >> 96, NOW + 86400, BAD)
    for name in ("seaport-free-listing.json", "safe-delegatecall.json", "safe-batch.json"):
        yield json.loads((EXAMPLES / name).read_text())
    yield json.loads(json.loads((EXAMPLES / "permit-unlimited.json").read_text())["params"][1])


@pytest.mark.parametrize("td", list(typed_examples()), ids=lambda td: td["primaryType"])
def test_hashes_match_eth_account(td):
    messages = pytest.importorskip("eth_account.messages")
    full = eip712.parse(td)  # eth_account wants EIP712Domain in types
    signable = messages.encode_typed_data(full_message=full)
    domain, message, _ = eip712.hashes(full)
    assert signable.header == domain
    assert signable.body == message


def test_domain_types_derived_when_left_out():
    td = dict(MAIL, types={k: v for k, v in MAIL["types"].items() if k != "EIP712Domain"})
    assert eip712.hashes(eip712.parse(td)) == eip712.hashes(eip712.parse(MAIL))


def test_bad_typed_data_is_reported():
    with pytest.raises(eip712.TypedDataError, match="contents is missing"):
        eip712.hashes(eip712.parse(dict(MAIL, message={k: v for k, v in MAIL["message"].items() if k != "contents"})))
    with pytest.raises(eip712.TypedDataError, match="out of range"):
        eip712.hashes(eip712.parse(permit2_single(1 << 160, 0, BAD)))


# ---------------------------------------------------------------- explanations


def test_unlimited_permit_to_unknown_spender():
    r = explain(permit(), now=NOW)
    assert r.title == "Token permit (ERC-2612)"
    assert "unlimited USDC" in text(r)
    assert levels(r) == ["warning", "warning"]
    assert [k for k, _ in r.hashes] == ["domain hash", "message hash", "digest (signed)"]


def test_small_permit_to_known_spender_is_quiet():
    r = explain(permit(spender=PERMIT2, value=5_000_000), now=NOW)
    assert "5 USDC" in text(r)
    assert r.findings == []


def test_permit_deadlines():
    assert "forever" in text(explain(permit(deadline=MAX), now=NOW))
    assert "already passed" in text(explain(permit(deadline=NOW - 60), now=NOW))
    assert "in 3 years" in text(explain(permit(deadline=NOW + 3 * 366 * 86400), now=NOW))


def test_permit2_allowance():
    r = explain(permit2_single((1 << 160) - 1, NOW + 30 * 86400, "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"), now=NOW)
    assert r.title == "Permit2 allowance"
    assert "Uniswap Universal Router" in text(r)
    assert "in 30 days" in text(r)
    assert levels(r) == ["warning"]  # unlimited, but to a known router


def test_fake_permit2_contract_is_danger():
    r = explain(permit2_single(1, NOW + 60, BAD, contract=BAD), now=NOW)
    assert levels(r)[0] == "danger"
    assert "calls itself Permit2" in r.findings[0].text


def test_seaport_listing_for_nothing():
    r = explain((EXAMPLES / "seaport-free-listing.json").read_text(), now=NOW)
    assert ("you receive", "nothing") in r.fields
    assert levels(r) == ["danger", "warning", "warning"]
    assert "ANY token" in text(r)


def test_seaport_real_sale_is_not_danger():
    td = json.loads((EXAMPLES / "seaport-free-listing.json").read_text())
    td["message"]["consideration"][0].update(recipient=ALICE, startAmount=str(10**18), endAmount=str(10**18))
    td["message"]["offer"] = td["message"]["offer"][:1]
    r = explain(td, now=NOW)
    assert ("you receive", "1 ETH") in r.fields
    assert "danger" not in levels(r)


def test_safe_delegatecall():
    r = explain((EXAMPLES / "safe-delegatecall.json").read_text(), now=NOW)
    assert r.title == "Safe transaction"
    assert levels(r) == ["danger"]
    assert "Bybit" in r.findings[0].text


def test_safe_multisend_batch_is_decoded():
    r = explain((EXAMPLES / "safe-batch.json").read_text(), now=NOW)
    t = text(r)
    assert "2 calls" in t
    assert "call 1: action" in t and "unlimited USDC" in t
    assert "adds owner" in t
    assert levels(r) == ["note", "warning", "warning", "danger"]


def test_multisend_roundtrip():
    inner = abi.selector("transfer(address,uint256)") + bytes(12) + bytes.fromhex(BAD[2:]) + (7).to_bytes(32, "big")
    packed = bytes([0]) + bytes.fromhex(USDC[2:]) + (0).to_bytes(32, "big") + len(inner).to_bytes(32, "big") + inner
    assert abi.multisend(packed) == [(0, USDC, 0, inner)]
    with pytest.raises(ValueError):
        abi.multisend(packed[:-1])


def test_siwe_message():
    r = explain((EXAMPLES / "siwe.json").read_text(), now=NOW)
    assert r.title == "Sign-in with Ethereum (EIP-4361)"
    assert ("site", "app.uniswap.org") in r.fields
    assert levels(r) == ["note"]


def test_personal_sign_digest_matches_eth_account():
    messages = pytest.importorskip("eth_account.messages")
    r = explain({"method": "personal_sign", "params": ["0x48656c6c6f", ALICE]})
    signable = messages.encode_defunct(hexstr="0x48656c6c6f")
    expected = keccak256(b"\x19" + signable.version + signable.header + signable.body)
    assert dict(r.hashes)["digest (signed)"] == "0x" + expected.hex()
    assert ("message", "Hello") in r.fields


def test_blind_hash_and_eth_sign():
    assert levels(explain({"method": "personal_sign", "params": ["0x" + "ab" * 32, ALICE]})) == ["warning"]
    assert levels(explain({"method": "eth_sign", "params": [ALICE, "0x" + "ab" * 32]})) == ["danger"]


def test_transaction_set_approval_for_all():
    data = abi.selector("setApprovalForAll(address,bool)") + bytes(12) + bytes.fromhex(BAD[2:]) + (1).to_bytes(32, "big")
    tx = {
        "method": "eth_sendTransaction",
        "params": [{"from": ALICE, "to": "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D", "data": "0x" + data.hex()}],
    }
    r = explain(tx)
    assert "every token you own" in text(r)
    assert levels(r) == ["warning", "warning"]


def test_unknown_selector_and_plain_send():
    assert "unknown (selector 0xdeadbeef)" in text(explain({"to": BAD, "data": "0xdeadbeef"}))
    assert ("action", "send 1.5 ETH") in explain({"to": BAD, "value": hex(15 * 10**17)}, chain=1).fields


def test_bare_calldata_approve():
    data = abi.selector("approve(address,uint256)") + bytes(12) + bytes.fromhex(BAD[2:]) + MAX.to_bytes(32, "big")
    r = explain("0x" + data.hex())
    assert "unlimited of the target token" in text(r)


def test_wallet_send_calls():
    data = abi.selector("transfer(address,uint256)") + bytes(12) + bytes.fromhex(BAD[2:]) + (2_500_000).to_bytes(32, "big")
    req = {
        "method": "wallet_sendCalls",
        "params": [{"chainId": "0x1", "calls": [{"to": USDC, "data": "0x" + data.hex()}, {"to": BAD, "value": "0x1"}]}],
    }
    r = explain(req)
    assert r.title == "Batch of 2 calls (wallet_sendCalls)"
    assert "sends 2.5 USDC" in text(r)


def test_unknown_type_lists_fields():
    r = explain(MAIL)
    assert ("from.name", "Cow") in r.fields
    assert levels(r) == ["note"]


# ---------------------------------------------------------------- command line


def test_cli_text_and_exit_codes(capsys):
    assert main([str(EXAMPLES / "seaport-free-listing.json"), "--now", str(NOW)]) == 3
    assert "DANGER" in capsys.readouterr().out
    assert main([str(EXAMPLES / "siwe.json")]) == 0
    assert main(["not a request"]) == 1


def test_cli_json(capsys):
    assert main([json.dumps(permit()), "--json", "--now", str(NOW)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["title"] == "Token permit (ERC-2612)"
    assert {f["level"] for f in out["findings"]} == {"warning"}


def test_cli_quiet_prints_one_line_per_problem(capsys):
    assert main([str(EXAMPLES / "seaport-free-listing.json"), "--quiet", "--now", str(NOW)]) == 3
    lines = capsys.readouterr().out.splitlines()
    assert lines and all(line.startswith(("DANGER: ", "WARNING: ")) for line in lines)


def test_cli_quiet_is_silent_without_problems(capsys):
    assert main([str(EXAMPLES / "siwe.json"), "-q"]) == 0
    assert capsys.readouterr().out == ""


def test_cli_quiet_and_json_cannot_be_combined():
    with pytest.raises(SystemExit):
        main([str(EXAMPLES / "siwe.json"), "--quiet", "--json"])


# ---------------------------------------------------------------- EIP-7702


def authorization_tx(**auth):
    return {"method": "eth_sendTransaction", "params": [{"from": ALICE, "to": ALICE, "chainId": "0x1", "authorizationList": [auth]}]}


@pytest.mark.parametrize("chain, nonce", [(0, 0), (1, 7), (8453, 128), (2**64, 2**32)])
def test_authorization_hash_matches_eth_account(chain, nonce):
    from eth_account.typed_transactions.set_code_transaction import Authorization

    r = explain(authorization_tx(chainId=chain, address=BAD, nonce=nonce))
    expected = Authorization(chain, bytes.fromhex(BAD[2:]), nonce).hash()
    assert dict(r.hashes)["authorization 1 hash"] == "0x" + bytes(expected).hex()


def test_delegation_on_every_chain_is_dangerous():
    r = explain(authorization_tx(chainId="0x0", address=BAD, nonce="0x7"))
    assert r.worst == "danger"
    assert "on every chain" in text(r)


def test_clearing_a_delegation_is_only_a_note():
    r = explain(authorization_tx(chainId=1, address="0x" + "0" * 40, nonce=8))
    assert r.worst == "note"
    assert "removes the delegation" in " ".join(v for _, v in r.fields)


def test_authorization_needs_an_address():
    with pytest.raises(eip712.TypedDataError):
        explain(authorization_tx(chainId=1, nonce=8))


# ---------------------------------------------------------------- known tokens


@pytest.mark.parametrize(
    "chain, address, expected",
    [
        (8453, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", ("USDC", 6)),
        (42161, "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", ("USDT", 6)),
        (10, "0x4200000000000000000000000000000000000006", ("WETH", 18)),
    ],
)
def test_l2_tokens_are_named_only_on_their_own_chain(chain, address, expected):
    assert known.token(address, chain) == expected
    assert known.token(address, 1) is None


def test_l2_token_amount_is_shown_in_units():
    data = abi.selector("transfer(address,uint256)") + bytes(12) + bytes.fromhex(BAD[2:]) + (2_500_000).to_bytes(32, "big")
    r = explain({"chainId": 8453, "to": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "data": "0x" + data.hex()})
    assert "sends 2.5 USDC" in text(r)


# --- Uniswap Universal Router ---------------------------------------------------

ROUTER = "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af"
WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
HOOK = "0x0000000000000000000000000000000000004444"
ME, THIS = "0x" + "0" * 39 + "1", "0x" + "0" * 39 + "2"  # MSG_SENDER and ADDRESS_THIS in router calls
POOL = "(address,address,uint24,int24,address)"
V3_IN = ["address", "uint256", "uint256", "bytes", "bool"]
PERMIT_SINGLE = ["((address,uint160,uint48,uint48),address,uint256)", "bytes"]


def enc(types, values):
    return pytest.importorskip("eth_abi").encode(types, values)


def v3_path(*parts):
    """token, fee, token, fee, token ... packed as in Uniswap v3."""
    out = b""
    for i, p in enumerate(parts):
        out += bytes.fromhex(p[2:]) if i % 2 == 0 else p.to_bytes(3, "big")
    return out


def router_tx(steps, deadline=NOW + 600, sender=ALICE, to=ROUTER):
    """steps: (command byte, types, values) each."""
    data = abi.selector("execute(bytes,bytes[],uint256)") + enc(
        ["bytes", "bytes[]", "uint256"], [bytes(c for c, _, _ in steps), [enc(t, v) for _, t, v in steps], deadline]
    )
    tx = {"to": to, "data": "0x" + data.hex(), "chainId": 1}
    if sender:
        tx["from"] = sender
    return {"method": "eth_sendTransaction", "params": [tx]}


def v4_swap(actions):
    """A V4_SWAP command from (action byte, types, values) each."""
    return (0x10, ["bytes", "bytes[]"], [bytes(a for a, _, _ in actions), [enc(t, v) for _, t, v in actions]])


def test_router_selectors():
    assert abi.selector("execute(bytes,bytes[],uint256)").hex() == "3593564c"
    assert abi.selector("execute(bytes,bytes[])").hex() == "24856bc3"


def test_decode_values_matches_eth_abi():
    types = ["(address,(address,uint24,int24,address,bytes)[],uint128,uint128)", "int24", "bytes[]", "bool"]
    values = [(USDC, [(WETH, 500, -10, HOOK, b"\x01\x02"), (PERMIT2, 3000, 60, BAD, b"")], 5, 7), -887272, [b"", b"ab" * 40], True]
    decoded = abi.decode_values(types, enc(types, values))
    start, path, amount, minimum = decoded[0]
    assert start == USDC and path[0] == [WETH, 500, -10, eip712.checksum(HOOK), b"\x01\x02"]
    assert path[1][4] == b"" and (amount, minimum) == (5, 7)
    assert decoded[1:] == [-887272, [b"", b"ab" * 40], True]
    with pytest.raises(ValueError):
        abi.decode_values(types, enc(types, values)[:-40])


def test_v3_swap_to_yourself_is_quiet():
    path = v3_path(USDC, 500, WETH)
    r = explain(router_tx([(0x00, V3_IN, [ME, 1000 * 10**6, 3 * 10**17, path, True])]), now=NOW)
    assert ("step 1: swap", "1,000 USDC for at least 0.3 WETH on Uniswap v3, to you (the sender)") in r.fields
    assert ("steps", "1 (Uniswap Universal Router)") in r.fields
    assert levels(r) == []


def test_v3_exact_output_path_runs_backwards():
    path = v3_path(WETH, 500, USDC)  # output first
    r = explain(router_tx([(0x01, V3_IN, [ALICE, 10**18, 4000 * 10**6, path, True])]), now=NOW)
    assert ("step 1: swap", f"at most 4,000 USDC for 1 WETH on Uniswap v3, to you ({ALICE})") in r.fields


def test_swap_output_to_someone_else_and_no_minimum():
    path = v3_path(USDC, 500, WETH)
    r = explain(router_tx([(0x00, V3_IN, [BAD, 10**6, 0, path, True])]), now=NOW)
    assert levels(r) == ["warning", "warning"]
    assert "sandwich" in text(r)
    assert f"{eip712.checksum(BAD)} receives the WETH from this swap, and it is not the address sending this transaction." in text(r)


def test_without_a_sender_a_stranger_recipient_is_only_a_note():
    path = v3_path(USDC, 500, WETH)
    r = explain(router_tx([(0x00, V3_IN, [BAD, 10**6, 1, path, True])], sender=None), now=NOW)
    assert levels(r) == ["note"] and "Make sure that is your address" in text(r)


def test_permit2_permit_for_another_spender_is_danger():
    details = (USDC, 2**160 - 1, NOW + 86400, 0)
    r = explain(router_tx([(0x0A, PERMIT_SINGLE, [(details, BAD, NOW + 600), b"\x00" * 65])]), now=NOW)
    assert levels(r) == ["danger"]
    assert "not for the router being called" in text(r)
    ok = explain(router_tx([(0x0A, PERMIT_SINGLE, [(details, ROUTER, NOW + 600), b""])]), now=NOW)
    assert levels(ok) == [] and "the router may spend unlimited USDC" in text(ok)


def test_permit2_transfer_to_someone_else():
    r = explain(router_tx([(0x02, ["address", "address", "uint160"], [USDC, BAD, 5 * 10**6])]), now=NOW)
    assert levels(r) == ["warning"]
    assert "receives 5 USDC taken from your wallet through Permit2" in text(r)
    assert levels(explain(router_tx([(0x02, ["address", "address", "uint160"], [USDC, ROUTER, 1])]), now=NOW)) == []


@pytest.mark.parametrize("bips, warned", [(25, False), (500, True)])
def test_pay_portion_fee(bips, warned):
    r = explain(router_tx([(0x06, ["address", "address", "uint256"], [WETH, BAD, bips])]), now=NOW)
    assert ("step 1: fee", f"{bips / 100:g}% of the WETH to {eip712.checksum(BAD)}") in r.fields
    assert levels(r) == (["warning"] if warned else [])


def test_unknown_command_and_allow_revert_flag():
    sweep = (0x80 | 0x04, ["address", "address", "uint256"], [WETH, ME, 0])
    r = explain(router_tx([(0x1F, ["uint256"], [1]), sweep]), now=NOW)
    assert ("step 1: command", "unknown (0x1f)") in r.fields
    assert ("step 2: sweep", "all WETH left in the router to you (the sender)") in r.fields
    assert levels(r) == ["warning"]


def test_sub_plan_steps_are_explained():
    inner = enc(["address", "address", "uint256"], [USDC, BAD, 10**6])
    r = explain(router_tx([(0x21, ["bytes", "bytes[]"], [bytes([0x05]), [inner]])]), now=NOW)
    assert ("step 1: sub-plan step 1: transfer", f"1 USDC to {eip712.checksum(BAD)}") in r.fields
    assert levels(r) == ["warning"]


def test_old_router_nft_commands_are_not_guessed():
    r = explain(router_tx([(0x10, ["uint256"], [1])], to="0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"), now=NOW)
    assert ("step 1: command", "NFT market command 0x10, not decoded") in r.fields


def single(min_out, fee=3000, hooks="0x" + "0" * 40):
    key = (USDC, WETH, fee, 60, hooks)
    return (0x06, [f"({POOL},bool,uint128,uint128,bytes)"], [(key, True, 1000 * 10**6, min_out, b"")])


SETTLE_ALL = (0x0C, ["address", "uint256"], [USDC, 1000 * 10**6])


def test_v4_swap_with_minimum_in_take_all_is_quiet():
    take_all = (0x0F, ["address", "uint256"], [WETH, 3 * 10**17])
    r = explain(router_tx([v4_swap([single(0), SETTLE_ALL, take_all])]), now=NOW)
    assert ("step 1: v4 action 1: swap", "1,000 USDC for at least 0 WETH (Uniswap v4, fee 0.3%)") in r.fields
    assert ("step 1: v4 action 2: pay", "up to 1,000 USDC, from you") in r.fields
    assert ("step 1: v4 action 3: receive", "the WETH from the swap (at least 0.3 WETH), to you") in r.fields
    assert levels(r) == []


def test_v4_swap_with_no_minimum_anywhere_and_output_elsewhere():
    take = (0x0E, ["address", "address", "uint256"], [WETH, BAD, 0])
    r = explain(router_tx([v4_swap([single(0, fee=0x800000, hooks=HOOK), SETTLE_ALL, take])]), now=NOW)
    assert ("step 1: v4 action 1: swap", "1,000 USDC for at least 0 WETH (Uniswap v4, dynamic fee)") in r.fields
    assert ("step 1: v4 action 3: receive", f"all the WETH from the swap, to {eip712.checksum(BAD)}") in r.fields
    assert sorted(levels(r)) == ["note", "warning", "warning"]
    assert "hook contract" in text(r) and "no later action sets a minimum" in text(r)


def test_real_v4_swap_example():
    r = explain((EXAMPLES / "uniswap-v4-swap-to-another-address.json").read_text(), now=NOW)
    assert ("to", f"{ROUTER} (Uniswap Universal Router (v4))") in r.fields
    assert ("step 1: v4 action 3: receive", "all the ETH from the swap, to 0x578aB972E8B3863940E58e89E59fD9017BC0f2AC") in r.fields
    assert levels(r) == ["warning", "warning"]


def test_router_deadline():
    r = explain(router_tx([(0x0B, ["address", "uint256"], [THIS, 10**18])], deadline=NOW - 60), now=NOW)
    assert ("step 1: wrap", "ETH into WETH, to the router, for a later step") in r.fields
    assert "The deadline has passed" in text(r)
