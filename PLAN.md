# FURY Implementation & Testing Plan (v1.0)

## Current State

```
fury-core   ✅ identity.rs  — BIP-32 NIP-06 derivation, BIP-340 Schnorr, mlock, ECDH
            ✅ event.rs     — NIP-01 event construction, SHA-256 ID, Schnorr verify
            ✅ nip44.rs     — NIP-44 v2 (ECDH + HKDF + ChaCha20-Poly1305 + HMAC)
            ✅ error.rs     — FuryError enum, FuryResult<T>
            🔲 transport.rs — not started (Arti/Tor; direct WebSocket works today)
fury-sign   🔲 main.rs      — identity CLI stub (generate / show / import not yet implemented)
            🔲 storage.rs   — encrypted-at-rest mnemonic persistence (not started)
fury-chat   ✅ main.rs      — two-terminal NIP-44 encrypted chat (direct relay, no Tor)
```

---

## Milestones

| # | Name | Crate(s) | Delivers |
|---|------|----------|---------|
| M0 | Foundation | fury-core | Identity + error model ✅ |
| M1 | Full key ring | fury-core | All coin keys + public-key extraction |
| M2 | Nostr event + NIP-44 | fury-core | NIP-01 events, NIP-44 v2 encryption ✅ |
| M2.5 | Two-terminal chat demo | fury-chat | Working CLI chat over live relay ✅ |
| M3 | Tor transport (Arti) | fury-core | All relay connections through embedded Tor |
| M4 | Encrypted storage | fury-sign | At-rest mnemonic protection |
| M5 | Full chat protocol | fury-chat | ChatSession API, MLS groups, Tor-routed |
| M5.5 | Push notifications | fury-push | Contentless APNs/FCM + optional UnifiedPush |
| M6 | Integration & E2E | all | Two-node message round-trip, benchmarks |
| M7 | Identity CLI | fury-sign | `generate` / `show` / `import` subcommands |
| M8 | Desktop app | fury-desktop | Cross-platform GUI via Tauri (macOS, Linux, Windows) |
| M9 | Mobile app | fury-android, fury-ios | UniFFI bindings → Kotlin (Jetpack Compose) + Swift (SwiftUI) |

---

## M0 — Foundation (DONE)

### Delivered
- `FuryIdentity::new(SecretString) -> FuryResult<Self>`
- BIP-32 HD derivation via `bip32::XPrv::derive_from_path`
- BIP-340 Schnorr signing via `k256::schnorr`
- Heap-allocated scalar, `mlock`ed, zeroized on `Drop`
- `FuryError` / `FuryResult<T>` with `thiserror`

### Tests to add (pre-M1 gate)

**File:** `fury-core/src/identity.rs` (inline `#[cfg(test)]`)

| Test | Method | Expected outcome |
|------|--------|-----------------|
| NIP-06 vector 0 | known mnemonic → known xonly pubkey | pubkey bytes match spec vector |
| NIP-06 vector 1 | second spec vector | same |
| Bad mnemonic | `new(invalid)` | `Err(FuryError::Identity(_))` |
| `sign` determinism | same key + msg twice | identical signatures |
| `sign` output length | `sig.to_bytes().len()` | 64 |
| Drop zeroizes | unsafe peek after drop | bytes are `0x00` |

**NIP-06 test vectors** (from nips.nostr.com/06):
```
mnemonic : "leader monkey parrot ring guide accident before fence cannon height naive bean"
pubkey   : 17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917

mnemonic : "what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade"
pubkey   : d41b22899549e1f3d335a31002cfd382174006d3d693e5851d3aed8b5fa84d33
```

---

## M1 — Full Key Ring

### Goal
Extend `FuryIdentity` to derive keys for all supported coin types and expose the Nostr xonly public key needed for NIP-01 events.

### New deps (`fury-core/Cargo.toml`)
No new crates — `bip32` and `k256` are already present.

### API to implement

```rust
// fury-core/src/identity.rs additions

pub enum CoinType { Nostr, Ethereum, Bitcoin }

impl FuryIdentity {
    /// xonly (32-byte) public key for NIP-01 events and NIP-44 encryption
    pub fn nostr_pubkey(&self) -> k256::schnorr::VerifyingKey;

    /// Derive a child wallet key at the BIP-44 path for the given coin.
    /// Returns a separate locked key handle — does NOT store inside FuryIdentity.
    pub fn wallet_key(&self, coin: CoinType) -> FuryResult<WalletKey>;

    /// Bech32-encoded npub (NIP-19) for display / sharing
    pub fn npub(&self) -> String;
}

pub struct WalletKey {
    key_bytes: Box<[u8; 32]>,  // same mlock pattern as FuryIdentity
}

impl WalletKey {
    pub fn sign_ecdsa(&self, hash: &[u8; 32]) -> FuryResult<k256::ecdsa::Signature>;
    pub fn address_ethereum(&self) -> [u8; 20];  // keccak256(pubkey)[12..]
}
```

**Derivation paths:**

```rust
impl CoinType {
    fn path(&self) -> &'static str {
        match self {
            CoinType::Nostr    => "m/44'/1237'/0'/0/0",
            CoinType::Ethereum => "m/44'/60'/0'/0/0",
            CoinType::Bitcoin  => "m/44'/0'/0'/0/0",
        }
    }
}
```

**npub encoding:** NIP-19 bech32 is `"npub" + bech32(xonly_pubkey_bytes)`. Use the `bech32` crate (`bech32 = "0.9"`). Add to workspace deps.

### Tests

| Test | Expected outcome |
|------|-----------------|
| NIP-06 vectors (see M0) | `nostr_pubkey()` matches known bytes |
| EVM address derivation | address matches reference (use ethers test wallet) |
| `WalletKey::Drop` | key bytes zeroized |
| `wallet_key` distinct from identity key | bytes differ across coin types |
| `npub` roundtrip | decode back to same 32 bytes |

---

## M2 — Nostr Event Layer (DONE)

### Goal
Implement NIP-01 event construction + ID computation, NIP-44 v2 encryption/decryption. This is the message payload layer — no network yet.

### New deps (`fury-core/Cargo.toml`)

```toml
serde       = { workspace = true }    # event serialization
serde_json  = { workspace = true }    # canonical JSON for event ID
sha2        = { workspace = true }    # SHA-256 for event ID (already transitive, make explicit)
chacha20poly1305 = { workspace = true } # NIP-44 v2 payload cipher
hmac        = { workspace = true }    # NIP-44 v2 key derivation (HKDF)
hkdf        = { workspace = true }
rand        = { workspace = true }
```

Add to workspace `Cargo.toml`: `serde = { version = "1", features = ["derive"] }`, `serde_json = "1"`, `chacha20poly1305 = "0.10"`, `hkdf = "0.12"`, `rand = "0.8"`.

### New file: `fury-core/src/event.rs`

**NIP-01 event structure:**

```rust
#[derive(Serialize, Deserialize)]
pub struct NostrEvent {
    pub id:         String,          // hex SHA-256 of canonical form
    pub pubkey:     String,          // hex xonly pubkey
    pub created_at: u64,             // unix timestamp
    pub kind:       u16,             // 1 = text note, 4 = DM, 44 = NIP-44 DM
    pub tags:       Vec<Vec<String>>,
    pub content:    String,
    pub sig:        String,          // hex BIP-340 Schnorr signature
}

impl NostrEvent {
    /// Canonical JSON for ID computation:
    /// [0, pubkey, created_at, kind, tags, content]
    fn canonical_bytes(&self) -> Vec<u8>;

    pub fn event_id(pubkey: &str, created_at: u64, kind: u16,
                    tags: &[Vec<String>], content: &str) -> [u8; 32];

    /// Build and sign a complete event
    pub fn sign(identity: &FuryIdentity, kind: u16,
                tags: Vec<Vec<String>>, content: String) -> FuryResult<Self>;

    pub fn verify(&self) -> FuryResult<()>;
}
```

**Event ID computation:**
```
id = SHA-256( UTF-8( JSON([0, pubkey_hex, created_at, kind, tags, content]) ) )
```
The canonical serialization must produce compact JSON with no whitespace, and fields in exactly the order above. Use `serde_json::json!` macro then `serde_json::to_string` — verify with reference implementations.

### New file: `fury-core/src/nip44.rs`

**NIP-44 v2 spec (XChaCha20-Poly1305 + HKDF-SHA256):**

```
conversation_key = HMAC-SHA256(key=priv_a_bytes XOR priv_b_bytes, msg=pub_b_xonly || pub_a_xonly)
 -- actually: --
conversation_key = secp256k1_ECDH(priv_a, pub_b)  [x-coordinate only, no hashing]
message_key      = HKDF-SHA256(ikm=conversation_key, salt=nonce[0..24], info="nip44-v2", len=76)
    → chacha_key     = message_key[0..32]
    → chacha_nonce   = message_key[32..44]
    → hmac_key       = message_key[44..76]
ciphertext       = XChaCha20-Poly1305-Encrypt(key=chacha_key, nonce=chacha_nonce, plaintext)
mac              = HMAC-SHA256(key=hmac_key, msg=nonce || ciphertext)
payload          = base64( version[1] || nonce[32] || ciphertext || mac[32] )
```

```rust
// fury-core/src/nip44.rs
pub fn encrypt(
    sender_key: &FuryIdentity,
    recipient_pubkey: &k256::schnorr::VerifyingKey,
    plaintext: &str,
) -> FuryResult<String>;   // base64 payload

pub fn decrypt(
    recipient_key: &FuryIdentity,
    sender_pubkey: &k256::schnorr::VerifyingKey,
    payload: &str,
) -> FuryResult<String>;   // plaintext
```

### Tests

| Test | Method | Expected |
|------|--------|----------|
| NIP-44 v2 vector set A | encrypt known plaintext | ciphertext matches spec |
| NIP-44 v2 vector set B | decrypt known payload | plaintext matches spec |
| NIP-44 roundtrip | encrypt then decrypt same key pair | plaintext recovered |
| NIP-44 wrong key | decrypt with different key | `Err(FuryError::Crypto(_))` |
| Event ID vector | canonical JSON → SHA-256 | matches nostr-tools reference |
| Event sign + verify | `sign` then `verify` | `Ok(())` |
| Tampered event | flip one bit in `sig` | `Err(_)` |

**NIP-44 v2 official test vectors:** available at `github.com/paulmillr/nip44` in `vectors.json`. Pull the first 5 encrypt and decrypt cases.

---

## M2.5 — Two-Terminal Chat Demo (DONE)

### Delivered
`fury-chat/src/main.rs` — interactive CLI that:
1. Reads `FURY_MNEMONIC`, `FURY_RECIPIENT` (hex pubkey), `FURY_RELAY` from env
2. Derives identity, computes NIP-44 conversation key via ECDH
3. Connects to a live Nostr relay via `tokio-tungstenite` (direct, no Tor)
4. Subscribes: `["REQ", "fury-chat", {"kinds":[4], "#p":[our_pubkey], "authors":[peer_pubkey]}]`
5. Stdin loop: reads a line → NIP-44-encrypts → signs kind:4 event → publishes
6. Receive task: decrypts kind:4 events from peer → prints to stdout

### How to run the demo (two terminals)
```bash
# Terminal A
FURY_MNEMONIC="leader monkey parrot ring ..." \
FURY_RECIPIENT="<bob_hex_pubkey>" \
FURY_RELAY="wss://nos.lol" \
cargo run -p fury-chat

# Terminal B
FURY_MNEMONIC="<bob mnemonic>" \
FURY_RECIPIENT="<alice_hex_pubkey from Terminal A>" \
FURY_RELAY="wss://nos.lol" \
cargo run -p fury-chat
```

Both sides will see each other's messages decrypted in real time.

---

## M3 — Tor Transport (Arti)

### Goal
Route all Nostr relay WebSocket connections through embedded Tor via `arti-client`. No external daemon. No relay ever sees the user's IP. Plus the Nostr relay client for publish and subscribe.

### New deps (`fury-core/Cargo.toml`)

```toml
arti-client       = { workspace = true }
tor-rtcompat      = { workspace = true }
tokio-tungstenite = { workspace = true }
url               = { workspace = true }
```

Already added to workspace in the last `Cargo.toml` update.

### New file: `fury-core/src/transport.rs`

**Tor bootstrap:**

```rust
use arti_client::{TorClient, TorClientConfig};
use tor_rtcompat::PreferredRuntime;

/// Bootstrapped Tor client — expensive to create, cheap to clone.
/// Call once at startup, share via Arc<TorClient<PreferredRuntime>>.
pub async fn bootstrap_tor() -> FuryResult<TorClient<PreferredRuntime>> {
    let config = TorClientConfig::default();
    Ok(TorClient::create_bootstrapped(config).await?)
}
```

Bootstrapping (~5-10 s on first run) downloads the Tor consensus and builds circuits. Subsequent calls reuse cached state from `~/.local/share/arti` (or platform equivalent).

**Nostr relay client:**

```rust
pub struct RelayClient {
    url: url::Url,
    tor: Arc<TorClient<PreferredRuntime>>,  // mandatory; no bypass
}

impl RelayClient {
    /// Connect to a Nostr relay through Tor.
    /// `tor` must come from `bootstrap_tor()` — no direct path available.
    pub async fn connect(
        relay_url: &str,
        tor: Arc<TorClient<PreferredRuntime>>,
    ) -> FuryResult<Self>;

    /// Publish a signed NIP-01 event.
    /// Sends: ["EVENT", <event_json>]
    /// Expects: ["OK", "<id>", true, ""]
    pub async fn publish(&self, event: &NostrEvent) -> FuryResult<()>;

    /// Subscribe and return a stream of matching events.
    /// Sends: ["REQ", "<sub_id>", <filter>]
    /// Yields each incoming ["EVENT", "<sub_id>", <event>] frame.
    pub async fn subscribe(
        &self,
        filter: SubscriptionFilter,
    ) -> FuryResult<impl Stream<Item = FuryResult<NostrEvent>>>;
}

pub struct SubscriptionFilter {
    pub authors: Vec<String>,   // hex pubkeys
    pub kinds:   Vec<u16>,
    pub since:   Option<u64>,
    pub limit:   Option<u32>,
}
```

**WebSocket over Tor stream:**

```rust
// Inside RelayClient::connect:
let host = url.host_str()...;
let port = url.port_or_known_default()...;

let tor_stream = tor.connect((host, port)).await?;  // DataStream: AsyncRead + AsyncWrite
let (ws, _) = tokio_tungstenite::client_async_tls(relay_url, tor_stream).await?;
```

`DataStream` implements the standard async I/O traits — `tokio-tungstenite` accepts it directly without any adapter.

**Privacy invariant:** `RelayClient` requires a `TorClient`. There is no `connect_direct()`. `bootstrap_tor()` is the only constructor for the `TorClient` in this module — you cannot get a `RelayClient` without going through Tor.

### Tests

| Test | Method | Expected |
|------|--------|----------|
| Tor bootstrap | `bootstrap_tor()` in test | `Ok(_)`, no panic (may be slow; gate behind `#[ignore]` for CI) |
| Relay publish (mock, direct) | publish event to in-process mock relay *without* Tor | mock receives valid `["EVENT", ...]` JSON |
| Relay subscribe (mock, direct) | subscribe, publish, receive | event matches what was published |
| `RelayClient` has no direct constructor | inspect public API | `connect_direct()` must not exist |

**Note on testing Tor in CI:** real Tor circuit tests are slow and network-dependent. Mock relay tests (no Tor, just WebSocket protocol) run in CI without `#[ignore]`. The Tor integration test is marked `#[ignore]` and runs manually or in a dedicated privacy-test job.

**Mock relay:** implement a minimal `tokio::net::TcpListener`-based WebSocket echo relay in `fury-core/tests/mock_relay.rs`. Accepts `["EVENT", ...]` frames, echoes back `["OK", id, true, ""]` and `["EVENT", sub_id, event]`.

---

## M4 — Encrypted Storage (`fury-sign`)

### Goal
Persist the mnemonic encrypted at rest. On Apple platforms use the Keychain for the encryption key; everywhere else derive it from a user passphrase.

### New deps (`fury-sign/Cargo.toml`)

```toml
fury-core        = { path = "../fury-core" }
chacha20poly1305 = { workspace = true }
argon2           = { workspace = true }   # passphrase KDF
serde_json       = { workspace = true }
```

Add to workspace: `argon2 = "0.5"`.

### New file: `fury-sign/src/storage.rs`

```rust
pub struct SeedStore {
    path: std::path::PathBuf,
}

/// On-disk format (JSON):
/// { "v": 1, "salt": "<base64>", "nonce": "<base64>", "ct": "<base64>" }
/// Key = Argon2id(passphrase, salt, m=65536, t=3, p=4) → 32 bytes
/// Cipher = XChaCha20-Poly1305(key, nonce, mnemonic_utf8)

impl SeedStore {
    pub fn new(path: impl Into<PathBuf>) -> Self;

    /// Encrypt and persist mnemonic. Passphrase is SecretString.
    pub fn save(&self, mnemonic: &SecretString, passphrase: &SecretString) -> FuryResult<()>;

    /// Load and decrypt mnemonic.
    pub fn load(&self, passphrase: &SecretString) -> FuryResult<SecretString>;

    /// Returns true if a store file exists at the path.
    pub fn exists(&self) -> bool;
}
```

**Argon2id parameters:** `m_cost = 65536` (64 MiB), `t_cost = 3` (iterations), `p_cost = 4` (parallelism). These are OWASP-recommended minimums for 2024. Encode parameters in the stored JSON so future upgrades can re-encrypt transparently.

**Apple Keychain (feature flag `keychain`):** When compiled with `--features keychain`, the 32-byte Argon2id key is itself encrypted under a Keychain item (`security-framework` crate). The user only needs to unlock their macOS login session, not enter a passphrase. Gate this behind `#[cfg(target_os = "macos")]`.

### Tests

| Test | Expected |
|------|----------|
| Save + load roundtrip | recovered mnemonic == original |
| Wrong passphrase | `Err(FuryError::Crypto(_))` (AEAD tag fails) |
| Tampered ciphertext | `Err(FuryError::Crypto(_))` |
| File format version field | `v` field == 1 in stored JSON |
| `exists()` before/after save | `false` then `true` |

Use a `tempfile::tempdir()` for test isolation.

---

## M5 — Chat Protocol (`fury-chat`)

### Goal
Wire together the lower layers into a working 1:1 messenger and lay the foundation for MLS group messaging.

### New deps (`fury-chat/Cargo.toml`)

```toml
fury-core  = { path = "../fury-core" }
fury-sign  = { path = "../fury-sign" }
tokio      = { workspace = true }
openmls    = { workspace = true }    # MLS RFC 9420
```

Add to workspace: `openmls = { version = "0.5", features = ["test-utils"] }`.

### New file: `fury-chat/src/protocol.rs`

**1:1 messaging:**

```rust
pub struct ChatSession {
    identity: FuryIdentity,
    relay:    RelayClient,
}

impl ChatSession {
    pub async fn new(mnemonic: SecretString, relay_url: &str,
                     tor: Arc<TorClient<PreferredRuntime>>) -> FuryResult<Self>;

    /// Send an encrypted direct message to a recipient npub
    pub async fn send(&self, recipient_npub: &str, plaintext: &str) -> FuryResult<()>;

    /// Poll for incoming messages since `since_timestamp`
    pub async fn receive(&self, since: u64)
        -> FuryResult<Vec<(k256::schnorr::VerifyingKey, String)>>;
}
```

**send() flow:**
1. Decode `recipient_npub` → `VerifyingKey`
2. `nip44::encrypt(&self.identity, &recipient_pubkey, plaintext)` → ciphertext
3. `NostrEvent::sign(&self.identity, 44, tags, ciphertext)` → event
4. `self.relay.publish(&event)`

**receive() flow:**
1. `self.relay.subscribe(SubscriptionFilter { authors: [sender], kinds: [44], since })`
2. For each event: `event.verify()` then `nip44::decrypt(&self.identity, &sender_pubkey, &event.content)`

**MLS group messaging (phase 2 within M5):**

MLS introduces a Delivery Service (DS) role. FURY uses Nostr events as the DS transport:
- `kind: 444` — MLS Welcome message (sent to new member)
- `kind: 445` — MLS Application message (group message)
- `kind: 446` — MLS Commit (key rotation)

```rust
pub struct MlsGroup {
    inner:   openmls::group::MlsGroup,
    relay:   RelayClient,
    identity: FuryIdentity,
}

impl MlsGroup {
    pub async fn create(identity: &FuryIdentity, relay: RelayClient,
                        member_npubs: &[&str]) -> FuryResult<Self>;
    pub async fn send(&mut self, plaintext: &str) -> FuryResult<()>;
    pub async fn receive(&mut self) -> FuryResult<Vec<String>>;
    pub async fn add_member(&mut self, npub: &str) -> FuryResult<()>;
    pub async fn remove_member(&mut self, npub: &str) -> FuryResult<()>;
}
```

MLS keypairs are derived separately from the Nostr identity (use `m/44'/1237'/1'/0/index` for MLS leaf keys so they never overlap).

### Tests

| Test | Expected |
|------|----------|
| 1:1 send + receive (mock relay) | plaintext recovered by recipient |
| send to unknown npub | `Err(FuryError::Identity(_))` |
| MLS group create + message | all initial members receive plaintext |
| MLS add member | new member receives subsequent messages |
| MLS forward secrecy | old epoch key cannot decrypt new epoch messages |
| Receive tamperedmessage | NIP-01 `verify()` fails before decryption |

---

## M5.5 — Push Notifications (`fury-push`)

### Goal
Wake mobile apps when new events arrive without leaking message content, sender identity, or communication frequency to Apple, Google, or any third party.

### Architecture

```
Nostr Relay
    │  event arrives matching subscriber's opaque token
    ▼
fury-push proxy  ←── knows: device token + relay URL only
    │  sends contentless ping
    ▼
APNs / FCM / UnifiedPush distributor
    │
    ▼
Device wakes → RelayClient.connect() → fetches events via Tor → decrypts locally
```

**Push payload (all backends):**
```json
{ "relay": "nos.lol" }
```
No pubkey, no event ID, no count, no preview. The relay hint lets the app reconnect to the right relay; everything else is resolved on-device.

### New crate: `fury-push`

A lightweight server process (deployable as a single static binary):

```rust
// fury-push/src/main.rs
// Watches a Nostr relay for events matching registered opaque tokens.
// Fires a contentless push via APNs, FCM, or ntfy (UnifiedPush) when triggered.
// Stores: (opaque_token → device_token, backend, relay_url) — no keys, no pubkeys.
```

Registration flow:
1. Client generates a random 32-byte `opaque_token`, registers `(opaque_token, device_token, relay_url)` with `fury-push`
2. Client publishes a Nostr event tagging `#t opaque_token` alongside the `#p` tag
3. `fury-push` subscribes to `{"#t": [opaque_token]}` — never sees the pubkey filter
4. On event arrival: fire ping, done

This decouples the push proxy from identity — even a compromised `fury-push` server cannot correlate device tokens to Nostr pubkeys.

### UnifiedPush backend

```toml
# fury-push/Cargo.toml
ntfy = "0.x"   # or raw HTTP POST to user-configured ntfy endpoint
```

UnifiedPush configuration stored in `fury-chat` settings:
```
FURY_PUSH_BACKEND=unifiedpush
FURY_PUSH_ENDPOINT=https://ntfy.example.com/mytopic
```

On de-Googled Android (GrapheneOS, CalyxOS), UnifiedPush is the default. On stock Android and iOS, APNs/FCM is default with UnifiedPush as opt-in.

**Batching:** `fury-push` coalesces multiple events into a single ping per device per N seconds (configurable, default 5 s) to reduce timing correlation metadata.

### Tests

| Test | Expected |
|------|----------|
| Registration stores no pubkey | inspect DB: only opaque_token present |
| Ping payload contains no message content | assert payload == `{"relay": "..."}` |
| Multiple events in window → single ping | coalescing works |
| UnifiedPush backend fires correct HTTP POST | mock ntfy endpoint receives correct request |
| Compromised proxy cannot link token to pubkey | opaque_token ≠ pubkey by construction |

---

## M6 — Integration & End-to-End

### Goal
Two independent `ChatSession` instances exchange messages through a real (local) Nostr relay over Tor. Benchmark identity creation and signing throughput.

### Infrastructure

Spin up in CI:
1. A local Nostr relay (`nostr-rs-relay` or `strfry` via Docker, bound to `127.0.0.1`)
2. Arti bootstrapped in-process — connects to the real Tor network, exits to `127.0.0.1` relay via a local exit (or use Arti's `address_filter` to allow `.onion`-free local connections in test mode)

For pure offline CI, mock relay tests (M3) cover the protocol; the E2E test is `#[ignore]` and runs in a network-enabled job.

### End-to-end test scenario

```
Alice                       Tor Network         Nostr Relay         Bob
 │  bootstrap_tor()             │                    │               │
 │  new(alice_mnemonic, tor)    │                    │               │
 │  new(bob_mnemonic, tor)      │                    │               │
 │                              │                    │               │
 │──send("hello")───────────────►  onion routed ────►               │
 │                              │                    │──deliver──────►
 │                              │                    │               │ receive()
 │                              │                    │               │ "hello" ✓
```

**File:** `fury-chat/tests/e2e.rs`

```rust
#[tokio::test]
async fn alice_sends_bob_receives() {
    let relay   = spawn_test_relay().await;
    let gateway = spawn_ohttp_gateway().await;

    let tor   = Arc::new(bootstrap_tor().await.unwrap());
    let alice = ChatSession::new(ALICE_MNEMONIC, &relay.url, tor.clone()).await.unwrap();
    let bob   = ChatSession::new(BOB_MNEMONIC,   &relay.url, tor.clone()).await.unwrap();

    let t0 = unix_now();
    alice.send(bob.identity.npub().as_str(), "hello fury").await.unwrap();

    let msgs = bob.receive(t0).await.unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].1, "hello fury");
}
```

### Benchmarks

**File:** `fury-core/benches/identity.rs` (using `criterion`)

| Benchmark | Target |
|-----------|--------|
| `FuryIdentity::new` | < 5 ms per call (BIP-32 derivation dominates) |
| `FuryIdentity::sign` | < 100 µs per call |
| `nip44::encrypt` 1 KB message | < 500 µs |
| `nip44::decrypt` 1 KB message | < 500 µs |

Add to workspace: `criterion = { version = "0.5", features = ["html_reports"] }` (dev-dep).

### Security validation

| Check | Method |
|-------|--------|
| Key bytes zeroized on drop | `unsafe` read after `drop(identity)` in test, assert all zeros |
| mlock effective (Linux) | read `/proc/self/status` `VmLck` before and after `FuryIdentity::new`; assert delta ≥ 4096 |
| No key in stack trace | compile with `RUSTFLAGS=-Z sanitize=memory` and run test suite |
| No key in core dump | set `ulimit -c unlimited`, crash a test process, `strings core \| grep <known_key_hex>` |

---

## Dependency Map (final workspace)

```toml
[workspace.dependencies]
# Identity
bip39           = "2.0"
bip32           = "0.5"
k256            = { version = "0.13", features = ["ecdsa", "schnorr", "sha256"] }
bech32          = "0.9"

# Event / Encryption
serde           = { version = "1", features = ["derive"] }
serde_json      = "1"
chacha20poly1305 = "0.10"
hkdf            = "0.12"
hmac            = "0.12"
rand            = "0.8"

# Transport
arti-client     = { version = "0.20", features = ["tokio", "rustls"] }
tor-rtcompat    = { version = "0.20", features = ["tokio", "rustls"] }
tokio-tungstenite = { version = "0.21", features = ["rustls-tls-webpki-roots"] }
url             = "2"
tokio           = { version = "1", features = ["full"] }

# Storage
argon2          = "0.5"

# Messaging
nostr-sdk       = "0.30"                  # NIP primitives reference
# openmls       = "0.5"                  # uncomment when M5 MLS begins
webrtc          = "0.11"                  # M6+ voice/video

# Utilities
secrecy         = "0.8"
zeroize         = { version = "1.7", features = ["derive"] }
memsec          = "0.6"
thiserror       = "1"
criterion       = { version = "0.5", features = ["html_reports"] }
tempfile        = "3"                     # test isolation
```

---

## M7 — Identity CLI (`fury-sign`)

**Goal:** replace the stub `main.rs` with a usable identity management CLI.

### Subcommands

```
fury-sign generate            # create new BIP-39 mnemonic, persist encrypted at rest
fury-sign show                # derive and print npub, EVM address, BTC address
fury-sign import <mnemonic>   # import existing mnemonic from another client
```

### Design notes
- Encrypted storage from M4 (`Argon2id + ChaCha20-Poly1305`) is a hard dependency.
- `show` prints all three identity surfaces side-by-side so users can verify cross-client portability.
- No private key material is ever printed; `show` outputs only public keys and addresses.

### Test gate
- `generate` → `show` round-trip: npub matches NIP-06 vector for known mnemonic.
- `import` followed by `show` produces identical output to `generate` on the same mnemonic.
- Wrong passphrase on unlock returns a clear error, never partial output.

---

## M8 — Desktop App (`fury-desktop`)

**Goal:** native cross-platform GUI for macOS, Linux, and Windows using [Tauri](https://tauri.app) (Rust backend + web frontend, no Electron, ~3 MB binary overhead).

### Architecture

```
fury-core  (all crypto, Tor, relay — unchanged)
    │  Tauri commands (thin async bridge)
    ▼
fury-desktop/src-tauri   (Rust shell, Tauri app harness)
fury-desktop/src         (TypeScript/React UI, local only — no CDN, no analytics)
```

The entire cryptographic and networking stack stays in `fury-core`. `fury-desktop` is a thin shell that exposes Tauri commands (`send_message`, `fetch_messages`, `get_identity`) and renders them.

### Key properties
- All Tor bootstrap and relay I/O runs in the Tauri async runtime — same `arti-client` path as CLI.
- No telemetry, no auto-update pings, no external asset loads.
- Keychain integration on macOS (`security-framework`) for mnemonic wrapping key.

### Test gate
- `cargo tauri build` succeeds on macOS and Linux CI runners.
- Send + receive round-trip through a local relay from the desktop UI.

---

## M9 — Mobile App (`fury-android` / `fury-ios`)

**Goal:** native Android and iOS apps sharing the full `fury-core` stack via [UniFFI](https://github.com/mozilla/uniffi-rs) (Mozilla's Rust → Kotlin/Swift bridge, used in production by Firefox for Android and Mozilla VPN).

### Architecture

```
fury-core  (Rust library, zero platform code)
    │  UniFFI generates bindings at build time
    ├──▶  fury-android/  (thin Kotlin shell, Jetpack Compose UI)
    └──▶  fury-ios/      (thin Swift shell, SwiftUI)
```

### UniFFI surface (`fury-core/src/ffi.rs`)
Expose a minimal async-safe API:
```rust
#[uniffi::export]
pub async fn send_message(mnemonic: String, relay: String, recipient_pubkey: String, plaintext: String) -> Result<(), FuryError> { … }

#[uniffi::export]
pub async fn fetch_messages(mnemonic: String, relay: String) -> Result<Vec<String>, FuryError> { … }
```

### Key properties
- Tor bootstrap runs inside the UniFFI async executor — same `arti-client` path, no daemon.
- Push notifications: contentless APNs/FCM ping (M5.5) wakes the app; all fetching happens through Tor inside `fury-core`.
- UnifiedPush is the default on de-Googled Android (GrapheneOS, CalyxOS).
- Keychain (iOS) and Android Keystore back the mnemonic wrapping key.

### Test gate
- `cargo build --target aarch64-linux-android` and `cargo build --target aarch64-apple-ios` succeed in CI.
- UniFFI-generated Kotlin bindings compile against the Android SDK.
- UniFFI-generated Swift bindings compile against the iOS SDK.

---

## CI Gates per Milestone

```yaml
# Each milestone merges only when all of its gates pass:

M0: cargo check + cargo test -p fury-core (NIP-06 vectors)
M1: M0 + wallet key derivation tests + npub roundtrip
M2: M1 + NIP-44 v2 official vectors + event sign/verify
M3: M2 + Tor roundtrip + mock relay publish/subscribe
M4: M3 + storage save/load roundtrip + wrong-passphrase rejection
M5: M4 + 1:1 message roundtrip (mock relay) + MLS group tests
M6: M5 + e2e test (local relay + Tor) + all benchmarks within budget
M7: M6 + fury-sign generate/show/import round-trip tests
M8: M7 + cargo tauri build (macOS + Linux) + desktop send/receive round-trip
M9: M8 + cross-compile to aarch64-linux-android + aarch64-apple-ios + UniFFI bindings compile
```

`cargo clippy -- -D warnings` and `cargo fmt --check` are required at every milestone.

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| `mlock` RLIMIT too low in CI | High | Low | CI runners (GitHub Actions) have sufficient default `RLIMIT_MEMLOCK` for small allocations; if a runner fails, raise the limit in the job via `ulimit -l unlimited` |
| `openmls` API churn between 0.4 and 0.5 | Medium | Medium | Pin exact version; isolate MLS behind a thin wrapper in `fury-chat/src/mls.rs` |
| Arti bootstrap slow on first run (~10 s) | High | Low | Cache consensus to disk (Arti does this by default); show progress in UI; pre-bootstrap in background at app start |
| Arti local relay connectivity in CI | Medium | Medium | Mark Tor E2E tests `#[ignore]`; mock relay tests cover the protocol; run Tor tests in a separate network-enabled CI job |
| `nostr-sdk 0.30` NIP-44 v2 incompatibility | Low | Medium | Implement NIP-44 natively in `fury-core/src/nip44.rs`; validate against official test vectors independently of nostr-sdk |
| BIP-32 key derivation incompatible with NIP-06 | Low | High | M0 test gate enforces exact NIP-06 pubkey vectors before any M1+ code merges |
| APNs/FCM push metadata subpoenaed by governments | High | Low | Payload carries no content; timing metadata is residual and unavoidable on stock iOS/Android |
| UnifiedPush distributor unavailable on target device | Medium | Low | Fall back to FCM/APNs automatically; UnifiedPush is opt-in enhancement, not a hard requirement |
| `fury-push` proxy correlates device tokens to identities | Low | High | Registration uses opaque random token; proxy never sees pubkeys — correlation is architecturally impossible |
