# FURY: SOVEREIGN STACK DESIGN SPECIFICATION (v1.1)

## I. CORE PHILOSOPHY

FURY is a high-performance, Rust-only sovereign communication and financial layer. It is built to be "immortal" — meaning it operates without a central company, foundation, or server infrastructure that can be seized, censored, or shut down.

**Key invariants:**
- All cryptographic keys derive from a single BIP-39 mnemonic the user controls
- No IP address ever reaches a Nostr relay unblinded (Tor via Arti mandate)
- No message metadata (typing, presence, read receipts) leaves the device
- Revenue (SaaS relays, DEX fees) is earned at the application layer; the protocol layer remains neutral

---

## II. THE SYMMETRICAL STACK

### 1. SEED (The Identity & Wealth Layer)

**Purpose:** A single 12- or 24-word BIP-39 mnemonic is the root of all identity and funds.

**Key derivation (BIP-32 HD wallet via `bip32` crate):**

| Purpose | Derivation Path | Standard |
|---|---|---|
| Nostr / Chat identity | `m/44'/1237'/0'/0/0` | NIP-06, SLIP-44 coin 1237 |
| Ethereum / EVM wallet | `m/44'/60'/0'/0/0` | BIP-44 |
| Bitcoin / Lightning | `m/44'/0'/0'/0/0` | BIP-44 |

**Why these paths matter:** Using BIP-32 child derivation (not raw seed slicing) ensures FURY keys are portable — any NIP-06-compliant Nostr client can import from the same mnemonic and derive the same identity key. Raw seed slicing produces keys that are incompatible with every other client.

**Signature scheme:**
- Nostr identity uses **BIP-340 Schnorr** signatures (`k256::schnorr`), not ECDSA.
  Nostr protocol (NIP-01) mandates Schnorr over secp256k1. The underlying scalar is the same 32 bytes derived from BIP-32; only the signing algorithm differs.
- EVM/Bitcoin signing will use ECDSA (`k256::ecdsa`) on their respective derived keys.

**Memory security model (implemented in `fury-core`):**

1. **Stack zeroization:** All intermediate buffers (BIP-39 seed, raw derivation output) are zeroized inline using the `zeroize` crate before the scope exits.
2. **Heap allocation:** The 32-byte private key scalar is stored in a `Box<[u8; 32]>` — a stable heap address, not the stack, which may be copied by the compiler between frames.
3. **`mlock(2)` via `memsec`:** The heap page holding the key is locked by the OS kernel immediately after allocation. A locked page is excluded from swap, hibernation images, and core dumps. `FuryIdentity::new` returns `FuryError::HardwareLock` if the kernel refuses (e.g. `RLIMIT_MEMLOCK` too low — a deployable error, not a panic).
4. **Ephemeral `SigningKey`:** `k256::schnorr::SigningKey` is never stored in the struct. It is reconstructed from the locked scalar bytes for each `sign()` call and dropped immediately. This minimises the time window during which the key exists outside the locked page.
5. **`munlock` + zeroize on `Drop`:** `FuryIdentity::drop` unlocks and then zeroes the page. Order matters: unlock first (so the OS can reclaim the page), then zeroize (so the data is gone before the allocator reuses the memory).

### 2. CORE (The Rust Machinery)

**Purpose:** Headless engine (`lib`) handling encryption and transport logic.

**Networking:**
- **Signaling:** Nostr (NIP-01 event format, NIP-44 encryption) for asynchronous message discovery. Nostr relays are stateless and interchangeable — no single relay failure breaks the system.
- **Privacy (Arti — embedded Tor):** All relay connections are routed through Tor via `arti-client`, the Tor Project's official pure-Rust Tor implementation. Arti bootstraps a Tor node in-process — no external daemon, no system dependency, ships inside the FURY binary. The Nostr relay never sees the user's real IP. `arti-client` exposes `DataStream` (implements `AsyncRead + AsyncWrite`), which `tokio-tungstenite` uses directly as the underlying stream for WebSocket connections.
- **P2P Media:** `webrtc-rs` for encrypted voice/video after signaling via Nostr.

**Performance:** Zero-cost abstractions, non-blocking I/O via `tokio`.

### 3. CHAT (The Sovereign Messenger)

**Purpose:** User interface and messaging logic.

**Privacy gates:**
- **Blinded fetch:** No direct connection to any Nostr relay; all requests are routed through Arti (embedded Tor).
- **Zero metadata:** No typing indicators, no "last seen", no read receipts.
- **Group messaging:** MLS (Messaging Layer Security, RFC 9420) via `openmls` for forward secrecy and post-compromise security in group chats. MLS provides per-message key ratcheting — compromise of one message key does not expose past or future messages.

**Push notification model:**

Mobile wake-up is a privacy boundary. APNs (Apple) and FCM (Google) are the only reliable background wake-up mechanisms on iOS and Android respectively. Every push routed through them creates a metadata record at Apple/Google:

- Which app received a push, when, and how often
- The sender identity (push proxy server IP / certificate)
- Frequency patterns that can confirm communication even without content

To contain this, FURY's push payload **never carries message content, sender identity, or event count** — only a relay hint sufficient to wake the app:

```json
{ "relay": "nos.lol" }
```

The app wakes, connects through its normal Tor-routed `RelayClient`, and fetches events itself. Message content never transits Apple/Google infrastructure.

**Push proxy threat model:** The push proxy (FURY-operated or self-hosted) knows a device token and a relay URL. It watches the relay for events matching an opaque token (no pubkeys, no keys), fires the ping, and discards the record. It cannot read message content even under legal compulsion.

**Residual metadata risk:** A contentless push from relay X at timestamp T still confirms "this device is a Nostr user who received an event at T." Mitigation: batch and delay push delivery at configurable intervals. Trades latency for reduced timing correlation.

**UnifiedPush:** For users who want to eliminate the Apple/Google intermediary entirely, FURY supports [UnifiedPush](https://unifiedpush.org) as a first-class alternative. UnifiedPush lets users route pushes through a self-hosted distributor (e.g. `ntfy`), removing Google/Apple from the delivery path. On de-Googled Android this is the default. On stock Android and iOS it is opt-in.

**Business model:**
- **SaaS Tier:** On-demand private Rust relay hosting for Pro users. The relay is a standard Nostr relay; FURY earns by running infrastructure, not by owning the protocol.
- **Value capture:** 0.1% fee on in-wallet DEX swaps via a smart contract fee tier.

---

## III. DATA FLOW (THE PRIVACY GATE)

```
User types message
       │
       ▼
[CHAT] NIP-44 encrypt with recipient's Nostr pubkey
       │
       ▼
[CORE] Serialize NIP-01 event, sign with BIP-340 Schnorr key
       │
       ▼
[CORE] Open DataStream through Arti (in-process Tor)
       │
       ▼
Tor Network  ←── sees: encrypted onion traffic only (IP hidden, content hidden)
       │
       ▼
Nostr Relay  ←── sees: signed event (cannot see user IP)
       │
       ▼
Recipient fetches via their own Arti stream → decrypts with NIP-44 key
```

**Identity creation path:**
```
12-word mnemonic
    │  bip39::Mnemonic::parse()
    ▼
512-byte BIP-39 seed
    │  bip32::XPrv::derive_from_path("m/44'/1237'/0'/0/0")
    ▼
32-byte secp256k1 scalar  ──→  mlock(heap page)
    │  k256::schnorr::SigningKey (ephemeral, per-sign)
    ▼
BIP-340 Schnorr signature
```

---

## IV. PROJECT REPOSITORY STRUCTURE

```text
fury/
├── fury-core/            # Rust engine — headless lib
│   └── src/
│       ├── identity.rs   # BIP-39 + BIP-32 + Schnorr + mlock + ECDH  ✅
│       ├── event.rs      # NIP-01 event construction, SHA-256 ID, verify  ✅
│       ├── nip44.rs      # NIP-44 v2: conversation_key, encrypt, decrypt  ✅
│       ├── transport.rs  # Arti/Tor relay client  ✅
│       └── error.rs      # FuryError enum + FuryResult<T>  ✅
├── fury-sign/            # HD wallet seed CLI (planned)
│   └── src/
│       └── main.rs       # generate / show / import (stub)
└── fury-chat/            # Two-terminal encrypted chat CLI  ✅
    └── src/
        └── main.rs       # NIP-44 send/receive via live relay (no Tor yet)
```

---

## V. NEXT IMPLEMENTATION STEPS

### Done ✅
1. **`FuryIdentity`** — BIP-39 → BIP-32 (NIP-06 path) → BIP-340 Schnorr, mlock, ECDH shared secret
2. **`NostrEvent`** — NIP-01 canonical JSON, SHA-256 ID, Schnorr sign + verify
3. **`nip44`** — Full NIP-44 v2: `conversation_key` (ECDH + HKDF-extract), `encrypt`/`decrypt` (per-message HKDF-expand → ChaCha20-Poly1305 + HMAC-SHA256)
4. **Multi-path wallet keys** — EVM (`m/44'/60'/0'/0/0`) and BTC (`m/44'/0'/0'/0/0`) key derivation with mlock; `npub()` NIP-19 bech32 encoding
5. **`fury-sign`** — CLI stub (generate/show/import planned)
6. **`fury-chat`** — Two-terminal encrypted chat demo over live relay (no Tor yet)

### Step 1 — Tor transport (`fury-core/src/transport.rs`)
Route all relay connections through Arti (embedded Tor, no daemon):
```rust
let tor = TorClient::create_bootstrapped(TorClientConfig::default()).await?;
let stream = tor.connect((relay_host, relay_port)).await?;  // DataStream: AsyncRead+AsyncWrite
let (ws, _) = tokio_tungstenite::client_async_tls(relay_url, stream).await?;
```
Replace the direct `connect_async` calls in `fury-chat/main.rs` with Tor-routed streams.
Privacy invariant: no `connect_direct()` — `TorClient` is mandatory.

### Step 2 — Persistence (`fury-sign/src/storage.rs`)
Encrypted at-rest mnemonic:
- Argon2id(passphrase, salt) → 32-byte key
- ChaCha20-Poly1305 wraps the mnemonic bytes
- On macOS, optionally use Keychain (`security-framework`) for the wrapping key

### Step 3 — MLS group messaging
Use MLS (RFC 9420) via `openmls` for group chats. FURY acts as its own Delivery Service via Nostr events (kind:444 = Welcome, kind:445 = Application message, kind:446 = Commit).

### Step 4 — `rlimit` detection
`mlock` fails on systems with low `RLIMIT_MEMLOCK`. Add a startup check and suggest `ulimit -l unlimited` on Linux. Never silently downgrade security.

---

## VI. LICENSE

MIT License.
