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

- **Protected:** message content (NIP-44 v2), and your IP address (Tor via Arti)
- **Not protected today:** sender and recipient identity, and the communication graph. 1:1
  messages expose both parties' long-term pubkeys to every relay, and to anyone who queries
  those relays. See [Communication graph leak](#communication-graph-leak) for details and the fix plan.
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
- **The communication graph is visible.** See the next section.

## Communication graph leak

### What leaks today
`fury-chat` sends every 1:1 message as a kind-4 event:

```json
{
  "pubkey": "<sender's long-term Nostr key>",
  "kind": 4,
  "created_at": <exact send time>,
  "tags": [["p", "<recipient's long-term Nostr key>"]],
  "content": "<NIP-44 v2 ciphertext>",
  "sig": "…"
}
```

- **Every relay the event reaches sees the sender, the recipient, the exact send time and the
  message size bucket.** NIP-44 padding hides the exact length, but not its rough size.
- **This isn't limited to relay operators.** Nostr relays answer public queries. Anyone can
  send `REQ {"kinds":[4], "#p":["<X>"]}` or `{"authors":["<X>"]}` to a relay and rebuild who
  talks to whom, when and how often. They can do it for past messages too, because relays
  store kind-4 events.
- **The receiver's subscription tells the relay the contact pair.** `fury-chat` subscribes
  with `authors: [peer]` and `#p: [me]`, so the relay learns about the pair even when nothing
  is sent.
- **Tor doesn't help here.** It hides IP addresses, but the identifiers in these events are
  long-term pubkeys, the same npubs users hand out. The graph is tied to identities
  directly, with no IP needed.
- **The planned push proxy (PLAN M5.5) would add another link.** An event would carry both
  the opaque `#t` token and the recipient's `#p` tag, so the proxy would see which device
  token belongs to which recipient pubkey.

A separate interoperability bug: kind 4 is defined by NIP-04 (AES-CBC content), but FURY puts
NIP-44 content in it. Other Nostr clients cannot read FURY's direct messages today.

### Mitigation plan (in priority order)
1. **Move 1:1 messages to NIP-17 with NIP-59 gift wrapping (PLAN M3.5).**
   - The message becomes an unsigned kind-14 *rumor*. It is sealed into a kind-13 event
     signed by the sender and NIP-44-encrypted to the recipient.
   - The seal is then wrapped in a kind-1059 event, signed by a **new random key for each
     message**, with `created_at` randomised up to 2 days into the past.
   - Relays and third parties then see only a one-time pubkey and the recipient's `p` tag.
     **The sender is hidden.**
   - This also fixes interoperability, because NIP-17 is the standard way to carry NIP-44
     direct messages.
   - Stop publishing kind 4 entirely.
2. **Subscribe without naming the contact.** Receivers subscribe only to
   `{"kinds":[1059], "#p":[me]}`, with no `authors` filter. This comes with step 1.
3. **Use dedicated inbox relays that require AUTH to read.**
   - Publish a kind-10050 inbox relay list (NIP-17).
   - Prefer relays that serve kind 1059 only to the NIP-42-authenticated recipient, so third
     parties can't list anyone's incoming messages.
   - The FURY-hosted relay tier (DESIGN.md) should enforce this by default.
   - Afterwards, only your own inbox relay's operator can see how many wrapped events you
     receive and when.
4. **Separate push from identity.**
   - Drop the `#t`-token-next-to-`#p` scheme.
   - Until step 5 lands, the push proxy necessarily learns which recipient key is behind a
     device token. So recommend a self-hosted proxy or UnifiedPush distributor, and document
     the linkage for the hosted proxy.
5. **Pairwise receiving keys (research).**
   - Derive a separate inbox key per contact from the seed (for example
     `m/44'/1237'/2'/0/<contact index>`), and exchange it in the first gift-wrapped message.
   - The recipient's `p` tag and subscription then name a pseudonym for each contact, not the
     npub, which hides the recipient from relays and from the push proxy.
   - Costs: key management, multi-device sync, and contact recovery from the seed.
   - This keeps the standard NIP-17 format, but a relay can still follow each pseudonym over
     time.
   - **Extension: rotating tags.** Instead of a fixed pseudonym, address messages to a tag each
     pair of contacts derives from their NIP-44 conversation key, for example
     `HKDF(conversation_key, "fury-inbox" ‖ epoch)` with a daily epoch. The relay then sees tags
     it can't link to a pubkey or across days. The cost is that this is no longer NIP-17, so it
     only works between FURY clients (details in PITCH.md → Positioning).
6. **Timing.**
   - NIP-59 already randomises `created_at`.
   - Add optional send jitter and batched fetches.
   - What remains is the arrival time at the relay and traffic analysis by a global passive
     adversary; this stays documented as out of scope.
7. **Groups (MLS, M5).**
   - Sign kind-445 events with per-message ephemeral keys.
   - Never put member pubkeys in tags.
   - Document that the group ID tag still reveals a group's activity volume to relays.
8. **Regression tests.**
   - Fail CI if any direct-message event FURY publishes carries the user's long-term pubkey
     as `pubkey`, or in any tag other than the gift wrap's recipient `p` tag.
   - Fail CI if any direct-message subscription filter contains `authors`.

**What remains after steps 1–3:**
- The recipient's inbox relay learns that pubkey X receives N wrapped events at around times T.
  The wrapped events themselves don't say who sent them.
- **The sender still shows up in two places:**
  - NIP-17 has the sender keep a copy wrapped to themselves (PLAN M3.5), stored on the
    sender's own relays with the sender's pubkey in its `p` tag. On its own, that copy looks
    like any other incoming message for the sender. But a relay that sees it uploaded over
    the sender's own authenticated connection, or at the same moment as the outgoing copy,
    can tell that the sender was sending, though not to whom.
  - A relay that requires NIP-42 AUTH before *accepting* events (an anti-spam measure NIP-59
    allows) learns who is writing each wrapped event.
- Step 5 removes the link to X's public identity. Choosing relays run by your own
  organisation, which delete events once delivered and keep no logs, keeps what remains inside
  that organisation (PITCH.md → Why not SimpleX?).
