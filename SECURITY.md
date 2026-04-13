# Security Policy

## Supported Versions

FURY is pre-1.0 software. Security fixes are applied to the `main` branch only.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities via GitHub's private security advisory mechanism:

1. Go to the [Security Advisories](https://github.com/sergey-melnychuk/fury/security/advisories/new) page
2. Click **"New draft security advisory"**
3. Describe the issue, affected component, and reproduction steps

You will receive an acknowledgement within **72 hours**. Confirmed vulnerabilities
will be patched and disclosed publicly once a fix is available, with credit to the
reporter unless anonymity is requested.

## Scope

In scope:

- `fury-core` — cryptographic primitives, key derivation, NIP-44 encryption, Tor transport
- `fury-sign` — mnemonic storage, key management CLI
- `fury-chat` — relay client, message handling

Out of scope:

- Vulnerabilities in upstream dependencies (`arti-client`, `openmls`, `k256`, etc.) —
  report these to the respective upstream projects
- Attacks that require physical access to an unlocked device
- Denial-of-service against public Nostr relays

## Threat Model

FURY's threat model is documented in [DESIGN.md](DESIGN.md). In summary:

- **Protected:** message content, sender/recipient identity, IP address, communication graph
- **Not protected:** the fact that a device is a Nostr user (observable from push timing),
  traffic volume and timing on the Tor circuit (global passive adversary), physical device seizure
- **Assumptions:** the user controls their mnemonic and device; the Tor network is not fully
  compromised; at least one honest Nostr relay is reachable

## Cryptographic Primitives

| Primitive | Implementation | Standard |
|-----------|---------------|---------|
| Key derivation | BIP-39 + BIP-32 (NIP-06 path) | `bip39`, `bip32` |
| Identity signing | BIP-340 Schnorr / secp256k1 | `k256` |
| Message encryption | NIP-44 v2: ECDH + HKDF + ChaCha20 + HMAC-SHA256 | `k256`, `hkdf`, `chacha20`, `hmac` |
| At-rest encryption | Argon2id + ChaCha20-Poly1305 | `argon2`, `chacha20poly1305` |
| Transport anonymity | Tor via Arti (pure-Rust, embedded) | `arti-client` |
| Memory protection | mlock(2) / munlock + zeroize on drop | `memsec`, `zeroize` |

NIP-44 v2 implementation is verified against the
[official test vectors](https://github.com/paulmillr/nip44).

## Known Limitations

- **No forward secrecy for 1:1 messages.** NIP-44 uses a static ECDH conversation key.
  MLS (planned, M5) provides per-message ratcheting for group chats.
- **Push timing metadata.** Contentless push pings confirm "this device received a Nostr
  event at time T" to Apple/Google. Mitigation: batched/delayed delivery (configurable).
  UnifiedPush eliminates this for users who opt in.
- **Mnemonic is the single point of compromise.** There is no multi-factor recovery.
  Loss of the mnemonic is permanent loss of identity.
