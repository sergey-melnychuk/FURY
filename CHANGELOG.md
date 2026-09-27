# Changelog

All notable changes to FURY are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Security
- Documented the communication-graph leak: kind-4 DMs expose sender and recipient pubkeys and exact timestamps to relays and to anyone who queries them. Added a mitigation plan (SECURITY.md) and milestone M3.5 (NIP-17 / NIP-59 gift wrap).
- Corrected the claim that the planned push proxy cannot link device tokens to pubkeys.

### Documentation
- NIP-44 is described correctly as ChaCha20 + HMAC-SHA256 (no Poly1305) in DESIGN.md, PLAN.md and this changelog.
- PLAN.md current state, milestone status and DESIGN.md next steps now reflect M1–M3 as done.
- Removed the duplicated `fury-sign` subcommand list from the README, and corrected the interoperability claim (kind 4 + NIP-44 isn't readable by other clients).
- Corrected the README comparison table:
  - Matrix needs no phone number.
  - FURY's push is planned, not done.
  - Signal and Matrix already send content-free pushes.
  - The MLS row no longer credits Signal, SimpleX or Matrix with MLS.
  - SimpleX sends content-free pushes too.
  - Briar runs Tor as a separate process and has no iOS app.
  - Matrix is partly Rust (the Conduit server and the matrix-rust-sdk core).
  - Added notes on group forward secrecy, push formats, Tor and Rust.
- Corrected the MLS description: Signal and WhatsApp groups don't use MLS; Wire and Cisco Webex do.
- README tagline no longer claims "no servers you don't own"; the push description is marked as planned (M5.5).
- PITCH.md:
  - Uses "non-EU" consistently (the UK is outside the EU).
  - Makes the Matrix argument about homeserver metadata rather than `matrix.org` traffic.
  - Reframes the journalist use case as newsrooms.
  - Adds a "Why not SimpleX?" chapter, checked against SimpleX v7.0.3 sources, positioning FURY around recoverable organisational identity and organisation-run relays.
- M3.5 is described as hiding the sender and reducing the graph leak, not closing it. SECURITY.md now lists what still leaks after it: the sender's self-copy, and AUTH-on-write relays.
- Documented rotating inbox tags as an option extending pairwise receiving keys (SECURITY.md step 5, PITCH.md).

---

## [0.1.0] — 2026-05-04

Initial public release. Milestones M0–M3 complete and verified.
M4–M7 are the next funded phase (encrypted storage, MLS groups, push notifications, identity CLI).

### M3 — Tor Transport (Arti)

- `fury-core/src/transport.rs`: `bootstrap_tor()` bootstraps an in-process Tor client via `arti-client` (no external daemon, no system dependency)
- `RelayClient`: connects to any Nostr relay over a Tor-routed WebSocket; `publish` and `subscribe` over the same stream
- Privacy invariant enforced in the type system: no `connect_direct()` path exists; a `TorClient` is required to construct a `RelayClient`
- `fury-chat` updated to route all relay I/O through Tor; first run prints Tor bootstrap progress (~10 s)

### M2.5 — Two-Terminal Encrypted Chat Demo

- `fury-chat/src/main.rs`: interactive CLI chat over a live public Nostr relay
- End-to-end encrypted with NIP-44 v2, Tor-routed, no account registration required
- Demo keys are the NIP-06 standard test vectors; safe to use for demonstration

### M2 — Nostr Event Layer + NIP-44 v2

- `fury-core/src/event.rs`: NIP-01 event construction, canonical JSON serialization, SHA-256 event ID computation, BIP-340 Schnorr sign and verify
- `fury-core/src/nip44.rs`: complete NIP-44 v2 implementation — secp256k1 ECDH, HKDF-SHA256 key derivation, per-message ChaCha20 encryption with HMAC-SHA256 authentication (NIP-44 uses no Poly1305)
- All encryption primitives verified against the [official NIP-44 test vectors](https://github.com/paulmillr/nip44)

### M1 — Full Key Ring

- BIP-44 key derivation for Ethereum (`m/44'/60'/0'/0/0`) and Bitcoin (`m/44'/0'/0'/0/0`) alongside Nostr identity
- `WalletKey`: heap-allocated, `mlock`-protected, zeroized on drop — same memory security model as identity key
- `npub()`: NIP-19 bech32 encoding of the Nostr public key for identity sharing
- All wallet key derivation tested for determinism and cross-coin isolation

### M0 — Foundation

- `FuryIdentity::new(mnemonic)`: BIP-39 → BIP-32 HD derivation (NIP-06 path `m/44'/1237'/0'/0/0`) → BIP-340 Schnorr keypair
- Private scalar stored on the heap in `Box<[u8; 32]>`, locked with `mlock(2)` via `memsec`, zeroized on `Drop`
- `mlock` failure is a hard error (`FuryError::HardwareLock`); no silent security downgrade
- `SigningKey` is reconstructed from the locked bytes per `sign()` call and dropped immediately
- Identity verified against both NIP-06 official test vectors

[0.1.0]: https://github.com/sergey-melnychuk/fury/releases/tag/v0.1.0
