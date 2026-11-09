# signcheck

[![tests](https://github.com/ngo-binh0108/signcheck/actions/workflows/tests.yml/badge.svg)](https://github.com/ngo-binh0108/signcheck/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**What does this wallet signature request really do? signcheck explains EIP-712 permits, Seaport
orders, Safe transactions and other wallet requests in plain words, flags the patterns wallet drainers use, and
prints the hashes your hardware wallet shows, so you can check them. It runs offline.**

```bash
pip install git+https://github.com/ngo-binh0108/signcheck
signcheck request.json
```

```
Token permit (ERC-2612)
  network          Ethereum (chain 1)
  app (as stated)  USD Coin (version 2)
  contract         0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
  owner            0x1234567890AbcdEF1234567890aBcdef12345678
  spender          0xBaD00000000000000000000000000000000000aD
  amount           unlimited USDC
  deadline         never
  in short         0xBaD00000000000000000000000000000000000aD may spend unlimited USDC from your wallet without asking again.

WARNING  0xBaD00000000000000000000000000000000000aD is not a contract signcheck recognises.
         Signatures like this cost no gas, so wallets often present them as harmless, but they
         are the most common way wallet drainers take tokens. Only sign if you started this on a
         site you trust.
WARNING  Unlimited: 0xBaD00000000000000000000000000000000000aD can take all of this token you
         hold, now and later, until you revoke it.
WARNING  There is no real deadline, so this stays usable forever by whoever holds the signature.

Hashes (compare with what your hardware wallet shows):
  domain hash      0x06c37168a7db5138defc7866392bb87a741f9b3d104deb5094588ce041cae335
  message hash     0x137a6e0b1ab9509dd38e34b4c96b9efae403a3ca1a70cfb2ecc89a61636727f5
  digest (signed)  0xf8a51a8bd78969481403959d5dcff2e93d8ff368245c095b2503dd358ca48afb
```

## Why

Many thefts don't need a transaction. A drainer site asks you to *sign* something: a token permit,
a Permit2 allowance, or a Seaport listing that sells your NFTs for nothing. It costs no gas, and a
wallet may show it as a wall of JSON or, on a hardware wallet, as two hashes. Once it's signed, the
attacker submits it and the assets are gone.

Multisigs have the same problem. In February 2025 Bybit's signers approved what their screens
showed as a routine transfer. It was a `delegatecall` that handed over the Safe, and about
$1.5 billion was taken. The fix the Safe community settled on is to check the hashes on the
hardware wallet against ones computed independently. signcheck computes them, and tells you what
the transaction does.

## What it understands

| Request | What signcheck shows and flags |
|---|---|
| ERC-2612 `Permit`, DAI-style permits | spender, amount (unlimited?), deadline; unknown spender, unlimited amount, no real deadline |
| Permit2 `PermitSingle` / `PermitBatch` / `PermitTransferFrom` (and witness variants) | each token and amount, expiry, spender; a fake "Permit2" domain pointing at another contract |
| Seaport `OrderComponents` | what you give, what you get back, who else is paid; **listings that pay you nothing**, "any token of a collection" offers |
| Safe `SafeTx` | target, value, `call` / `delegatecall`, decoded calldata, every call inside a MultiSend batch; **delegatecalls**, owner, threshold, module, guard and implementation changes, gas refunds |
| `personal_sign` | the text, Sign-In with Ethereum (site shown), bare 32-byte hashes |
| `eth_sign` | always dangerous |
| `eth_sendTransaction`, `wallet_sendCalls`, bare calldata | `approve`, `increaseAllowance`, `setApprovalForAll`, transfers, Permit2 `approve`, Safe settings calls, `multiSend` |
| anything else in EIP-712 | every field, with addresses named where known |

It also gives the EIP-712 **domain hash** and **message hash** that hardware wallets such as
Ledger show for typed data they can't display in full, and the final digest. For `personal_sign` it gives the
EIP-191 digest.

## Usage

signcheck reads a JSON-RPC request as a dapp sends it, the typed data alone, a transaction object,
or `0x` calldata:

```bash
signcheck request.json                         # a file
pbpaste | signcheck                            # stdin (Windows: Get-Clipboard | signcheck)
signcheck '{"method":"personal_sign","params":["0x48656c6c6f","0x1234..."]}'
signcheck 0x095ea7b3000000000000000000000000...  # bare calldata
signcheck safe-tx.json --json                  # machine-readable
signcheck tx.json --chain 8453                 # chain for requests that don't name one (default 1)
```

The exit status is `3` when a danger was found, so you can use it in scripts and CI checks
of Safe proposals. It is `0` otherwise, and `1` on errors.

The [examples](examples/) folder has one request of each kind, including a Seaport listing for
nothing and a Safe delegatecall modelled on the Bybit transaction:

```
$ signcheck examples/safe-delegatecall.json
Safe transaction
  network    Ethereum (chain 1)
  contract   0x5afe5afE5afE5afE5afE5aFe5aFe5Afe5Afe5AfE
  to         0xC0FfEE0000000000000000000000000000c0fFEe
  value      0 ETH
  operation  delegatecall (1)
  nonce      71
  function   transfer(address to,uint256 amount)
  action     sends 0 raw units of token 0xC0FfEE0000000000000000000000000000c0fFEe to 0xBaD00000000000000000000000000000000000aD

DANGER   delegatecall: 0xC0FfEE0000000000000000000000000000c0fFEe runs its code as the Safe
         itself, so it can change owners or the implementation and move everything the Safe
         holds. Bybit lost about $1.5 billion in February 2025 after its signers approved a
         delegatecall like this. Only sign if you know exactly what this contract is.
```

## Where to get the request

- **Browser wallet:** open the dapp's developer console and look for the `eth_signTypedData_v4`
  call, or copy the typed data most wallets show in an "advanced" or "raw data" view.
- **Safe:** the Safe web app shows the transaction's `to`, `value`, `data`, `operation` and `nonce`
  under *Advanced details*. Put them into a `SafeTx` file like
  [examples/safe-batch.json](examples/safe-batch.json). Get them from more than one source if
  you're worried the front end itself is compromised, as it was at Bybit.

## Limits

- **It works offline,** so it can't see on-chain state. It doesn't know whether an address is a
  contract or a wallet, what a token's decimals are (apart from a few well-known tokens on Ethereum, Base, Arbitrum and OP Mainnet),
  or what an unknown contract's code does. "Not a contract signcheck recognises" means *check it
  yourself*. It doesn't mean the address is malicious.
- The list of known contracts is short on purpose: Permit2, Seaport, the main Uniswap, 1inch, 0x
  and CoW contracts, and Safe's MultiSend. A name is only shown on the chains where that address is
  that contract.
- Treat a clean report as "nothing obviously wrong", not "safe". If you didn't expect to sign
  something, don't.

## Development

The only runtime dependency is Python 3.9+. Keccak-256 is implemented in the package. The tests
check it against pycryptodome, and check every EIP-712 and EIP-191 hash against eth-account.

```bash
pip install -e ".[test]"
pytest
```

## License

MIT
