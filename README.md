# FURY

[![CI](https://github.com/sergey-melnychuk/fury/actions/workflows/ci.yml/badge.svg)](https://github.com/sergey-melnychuk/fury/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Sovereign communication stack. One mnemonic. No servers you don't own. No IP visible to relays.**

Your 12-word BIP-39 seed phrase is your identity — one mnemonic deterministically derives your Nostr keypair, your EVM signing key, and your Bitcoin signing key. FURY is a pure-Rust encrypted messenger that routes every byte through embedded Tor and encrypts every message with NIP-44 v2. There is no account to register, no phone number to verify, no company to subpoena, and no single relay that can silence you.

---

## Demo

Two terminals. Real Nostr relay. End-to-end encrypted. Tor-routed.

```bash
# Terminal A
FURY_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
FURY_RECIPIENT="17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917" \
FURY_RELAY="wss://nos.lol" \
cargo run -p fury-chat

# Terminal B
FURY_MNEMONIC="leader monkey parrot ring guide accident before fence cannon height naive bean" \
FURY_RECIPIENT="e8bcf3823669444d0b49ad45d65088635d9fd8500a75b5f20b59abefa56a144f" \
FURY_RELAY="wss://nos.lol" \
cargo run -p fury-chat
```

These are the NIP-06 standard test vectors — safe to use as demo keys. Use your own mnemonic for real conversations; run with `-- --print-pubkey` to get your address.

Both sides will print `bootstrapping Tor (first run ~10 s)...` and then exchange encrypted messages. The relay sees signed NIP-01 events. It never sees your IP.

---

## Why FURY

| | FURY | Signal | Session | SimpleX | Briar | Matrix |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| No phone number | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ |
| No central company infra | ✅ | ❌ | ❌ | ❌ | ✅ | varies |
| Tor-native, no daemon | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| Open relay network | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| One seed → identity + signing keys | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Contentless push pings | ✅ | ❌ | ❌ | N/A | N/A | ❌ |
| NIP-44 v2 (official vectors) | ✅ | — | — | — | — | — |
| Pure Rust, no JVM/runtime | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| MLS forward secrecy (groups) | 🔲 | ✅ | ❌ | ✅ | ❌ | ✅ |
| Mobile app (UniFFI roadmap) | 🔲 | ✅ | ✅ | ✅ | ✅ | ✅ |

**Session** is the closest ancestor: seedphrase identity, no phone number, end-to-end encrypted. FURY extends the idea with Tor built into the binary, a lean HD signer (same seed → Nostr identity + EVM + BTC signing keys), and a protocol layer (Nostr) that no single organization owns.

**FURY is not a closed ecosystem.** The underlying protocol is standard Nostr (NIP-01 + NIP-44). Any Nostr client — Damus, Amethyst, Snort, Iris — can message a FURY user today. FURY starts with an existing network of thousands of relays and hundreds of thousands of users; it does not need to bootstrap one from scratch.

---

## How it works

```
You type a message
       │
       ▼  NIP-44 v2 encrypt
       │  (ECDH shared secret → HKDF → ChaCha20 + HMAC-SHA256)
       ▼
NIP-01 event  ←  BIP-340 Schnorr signed with your Nostr key
       │
       ▼  Arti (embedded Tor, no daemon)
       │
Tor Network  ──── sees: encrypted onion traffic only
       │           your IP is never in this path
       ▼
Nostr Relay  ──── sees: signed event JSON, no plaintext, no IP
       │
       ▼  peer fetches via their own Arti stream
       │
Peer decrypts with NIP-44 conversation key
```

**Identity creation:**

```
12-word BIP-39 mnemonic
    │  bip39::Mnemonic → 512-byte seed
    ▼
BIP-32 derivation  m/44'/1237'/0'/0/0  (NIP-06, SLIP-44)
    │
    ▼  32-byte secp256k1 scalar
    │  heap-allocated, mlock(2)-protected, zeroized on Drop
    ▼
BIP-340 Schnorr keypair   →  Nostr identity
m/44'/60'/0'/0/0          →  Ethereum wallet
m/44'/0'/0'/0/0           →  Bitcoin / Lightning wallet
```

The private scalar is never on the stack. The OS cannot swap it to disk. It is zeroed when the identity is dropped.

---

## Stack

```
fury-core     Pure-Rust headless library
  identity    BIP-39 / BIP-32 / NIP-06 / BIP-340 Schnorr / mlock / ECDH
  event       NIP-01 event construction, SHA-256 ID, Schnorr verify
  nip44       NIP-44 v2: conversation_key, encrypt, decrypt (official vectors ✅)
  transport   Arti/Tor relay client: bootstrap, publish, subscribe

fury-chat     Two-terminal encrypted chat CLI (works today)
fury-sign     Identity & signing CLI (planned)
                generate  — create a new BIP-39 mnemonic, persist encrypted at rest
                show      — derive and print Nostr npub, EVM address, Bitcoin address
                import    — import an existing mnemonic
                generate  — create a new BIP-39 mnemonic, persist encrypted at rest
                           (Argon2id + ChaCha20-Poly1305, macOS Keychain for wrapping key)
                show      — derive and print Nostr npub, Ethereum address, Bitcoin address
                import    — import an existing mnemonic from another wallet
```

### Cryptographic primitives

| Purpose | Primitive | Crate |
|---------|-----------|-------|
| Key derivation | BIP-39 + BIP-32 (NIP-06 path) | `bip39`, `bip32` |
| Identity signing | BIP-340 Schnorr over secp256k1 | `k256` |
| Key agreement | secp256k1 ECDH (x-coordinate) | `k256` |
| Message encryption | ChaCha20 stream cipher | `chacha20` |
| Message authentication | HMAC-SHA256 | `hmac`, `sha2` |
| Key derivation (NIP-44) | HKDF-SHA256 | `hkdf` |
| Tor transport | Arti (pure-Rust, embedded) | `arti-client` |
| Memory protection | mlock(2) / munlock | `memsec` |

---

## Group messaging

FURY uses **MLS (Messaging Layer Security, RFC 9420)** for group chats — the same protocol that powers Signal and WhatsApp groups. MLS provides two properties no simpler scheme can: *forward secrecy* (compromising a key today cannot decrypt past messages) and *post-compromise security* (after a device is compromised, the group automatically heals on the next key rotation).

Nostr events serve as FURY's Delivery Service (DS), the role normally played by a central server in MLS:

| Nostr kind | MLS message | Purpose |
|-----------|-------------|---------|
| `444` | Welcome | Onboard a new group member |
| `445` | Application | Encrypted group message |
| `446` | Commit | Key rotation, add/remove member |

All three event types are NIP-44 encrypted. Because Nostr is the DS, there is no MLS server to seize — any relay that stores Nostr events can carry MLS traffic.

MLS leaf keys are derived separately from the Nostr signing key (`m/44'/1237'/1'/0/<index>`) so group membership keys never collide with identity keys.

**Status:** planned for M5. 1:1 NIP-44 chat works today.

---

## Privacy model

**What the relay learns:** your signed event JSON (pubkey, timestamp, encrypted content). It cannot read the message. It cannot learn your IP (Tor). It can learn your pubkey if you publish, but Nostr pubkeys are designed to be public.

**What Tor learns:** circuit construction metadata. Your messages are onion-encrypted layers deep; Tor nodes see only the next hop.

**What Apple/Google learn (mobile, push notifications):** a contentless ping — `{"relay":"nos.lol"}` — with no message content, no sender identity, no event count. The device wakes, connects through Tor, and fetches events itself. Nothing sensitive transits Apple/Google infrastructure. For complete independence, [UnifiedPush](https://unifiedpush.org) support is planned as a first-class alternative.

**What is stored on disk:** nothing yet (M4). When persistence lands, the mnemonic will be wrapped by Argon2id + ChaCha20-Poly1305 with parameters at the 2024 OWASP minimum. On macOS, the wrapping key will live in Keychain.

---

## Roadmap

| Milestone | Status | Delivers |
|-----------|--------|---------|
| M0 — Foundation | ✅ | Identity, key derivation, mlock |
| M1 — Wallet keys | ✅ | EVM/BTC key derivation, npub encoding |
| M2 — Nostr event + NIP-44 | ✅ | NIP-01 events, NIP-44 v2 encryption |
| M2.5 — Chat demo | ✅ | Two-terminal encrypted chat over live relay |
| M3 — Tor transport | ✅ | All relay connections through embedded Arti |
| M4 — Encrypted storage | 🔲 | Argon2id-protected mnemonic at rest |
| M5 — Full chat protocol | 🔲 | ChatSession API, MLS groups |
| M5.5 — Push notifications | 🔲 | Contentless APNs/FCM + UnifiedPush |
| M6 — Integration & E2E | 🔲 | Two-node round-trip, benchmarks |
| M7 — Identity CLI | 🔲 | `fury-sign` generate / show / import |
| M8 — Desktop app | 🔲 | Tauri GUI — macOS, Linux, Windows |
| M9 — Mobile app | 🔲 | UniFFI → Android (Kotlin) + iOS (Swift) |

See [PLAN.md](PLAN.md) for detailed specs and test gates per milestone.

---

## Mobile

`fury-core` is a headless Rust library with no platform dependencies. The path to mobile is [UniFFI](https://github.com/mozilla/uniffi-rs) (Mozilla's Rust → Kotlin/Swift bridge, used in production by Firefox, Fenix, and Mozilla VPN):

```
fury-core  (Rust library, no platform code)
    │  UniFFI generates bindings
    ▼
fury-android  (thin Kotlin shell, Jetpack Compose UI)
fury-ios      (thin Swift shell, SwiftUI)
```

The entire cryptographic stack — key derivation, NIP-44 encryption, Tor bootstrap, relay client — lives in `fury-core` and is shared across CLI, Android, and iOS without modification. Platform code handles only UI and OS integration (push tokens, Keychain, background fetch). This is planned for post-M6.

---

## Build

```bash
# Requires Rust stable (1.85+)
cargo build --release

# Run all tests (includes NIP-44 official test vectors)
cargo test

# Lint
cargo clippy -- -D warnings
```

The first `cargo run -p fury-chat` build takes a few minutes — Arti pulls in the Tor consensus engine. Subsequent builds are incremental.

**Dependencies of note:** no OpenSSL, no system Tor daemon, no Node.js, no JVM. The full dependency tree is pure Rust except `libc` for the `mlock(2)` syscall wrapper.

---

## Security notes

- Private key scalars live on the heap in `Box<[u8; 32]>`, never on the stack.
- `mlock(2)` prevents the OS from paging the key to swap or including it in core dumps. `FuryIdentity::new` returns `Err(FuryError::HardwareLock)` — never silently downgrades — if the kernel refuses.
- `SigningKey` is reconstructed from the locked bytes per `sign()` call and dropped immediately.
- `Drop` calls `munlock` then `zeroize`. Order is intentional: unlock before zeroing so the allocator never reuses a still-locked page.
- NIP-44 v2 implementation is verified against the [official test vectors](https://github.com/paulmillr/nip44).

---

## Contributing

Bug reports, protocol questions, and security disclosures are welcome via [GitHub Issues](https://github.com/sergey-melnychuk/fury/issues). For responsible disclosure of security vulnerabilities, open a private security advisory on GitHub rather than a public issue.

All contributions are MIT-licensed.

---

## License

[MIT](LICENSE) — Copyright (c) 2026 Sergey Melnychuk
