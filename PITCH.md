# FURY — Sovereign Communication Stack
## Problem Statement & Development Roadmap

> Notes marked **Status** compare this pitch with what the code does today (v0.1.0, M0–M3).
> See [SECURITY.md](SECURITY.md) and [PLAN.md](PLAN.md) for details.

---

## The Problem

Secure communication is critical infrastructure. Yet every widely-deployed encrypted messenger
today depends on infrastructure or corporate entities subject to non-EU jurisdiction:

- **Signal** is a US non-profit, incorporated under US law, subpoenable by US courts, and
  requires a phone number — a government-issued, telecom-linked identifier — to register.
- **WhatsApp** is owned by Meta, a US corporation with a documented history of bulk metadata
  collection and legal compliance with US intelligence requests.
- **Matrix** is decentralised and self-hostable, but most accounts live on the `matrix.org`
  homeserver, run by a UK foundation. And every homeserver, self-hosted or not, sees room
  membership, message timing and its users' IP addresses; federation copies room membership
  to every server taking part in the room.

The consequences are concrete. Newsrooms coordinating cross-border investigations,
diplomats operating in hostile-jurisdiction countries, civil society organisations working
under surveillance, and public servants handling sensitive policy discussions are all
currently forced to choose between convenience and genuine operational security — with no
EU-sovereign alternative that meets professional-grade requirements.

## Who Needs This Today

**EU diplomatic staff in hostile-jurisdiction countries** are the clearest case. An embassy
employee in a country with active signal intelligence capabilities — coordinating with local
contacts, exchanging operational assessments, or simply arranging logistics — currently has
no sovereign option. Signal is US-incorporated and phone-number-linked: a local SIM card
issued under a real-name registration regime is an identity anchor, not a pseudonym.
WhatsApp is Meta. Classified channels do not cover day-to-day coordination. The gap between
"classified" and "plaintext email" is where operational security breaks down in practice,
and it is currently filled by US-controlled commercial software.

**Investigative newsrooms** working cross-border face the same gap from a different angle.
Reporters, editors and fixers in several countries need to know they are talking to their own
colleagues, and to keep their accounts when a phone is lost or seized. They also need
outsiders to be unable to rebuild who talked to whom, when, and how often, which is often
more damaging than message content. Consumer messengers give them either a phone-number
identity or a provider that sees the graph. (For a first contact with an anonymous source,
where nobody should be able to link the two, SimpleX is the better tool today; see
[Why not SimpleX?](#why-not-simplex).)

> **Status (Sep 2026):** FURY does not hide the communication graph yet either. Today's 1:1 messages are
> kind-4 events carrying the sender's and recipient's long-term pubkeys and the exact send time.
> Relays, and anyone who queries them, can see who talks to whom. The fix is milestone M3.5
> (NIP-17 / NIP-59 gift wrap), and even after it the recipient's inbox relay sees when messages
> arrive. See [SECURITY.md → Communication graph leak](SECURITY.md#communication-graph-leak).

**Civil society organisations** operating in restricted jurisdictions — human rights monitors,
election observers, legal aid networks — face coordinated infrastructure attacks and legal
pressure on their communication providers. A tool with no central operator to subpoena and
no IP addresses visible to relay operators removes the two most common attack vectors.

> **Status (Sep 2026):** **IP addresses:** done. All relay traffic goes through embedded Tor (M3), in the CLI;
> the desktop and mobile apps don't exist yet. **No central operator:** true at the protocol
> level. The planned FURY-hosted relay tier and push proxy (M5.5) would be operators that can be
> subpoenaed, and the push proxy could link device tokens to recipient pubkeys.

**Public sector teams handling sensitive policy** — procurement officers, negotiators,
regulators — increasingly operate across borders and devices without access to classified
infrastructure, yet deal with information that is commercially or politically sensitive.
Consumer messengers are the de-facto standard. That is the actual threat surface.

In all four cases the requirement is the same: communication that leaves no exploitable
metadata trail, runs on no infrastructure that a hostile actor can seize or subpoena,
and requires no identity anchor beyond a key the user controls.

> **Status (Sep 2026):** The "no identity anchor beyond a key the user controls" requirement is met. The "no
> exploitable metadata trail" requirement is **not met yet** (see the note above).

---

## The Gap

The gap is not just the application layer. The problem runs deeper:

1. **Identity is phone-number-bound.** A phone number is a real-world identity anchor
   controlled by a telecom operator, trivially linkable to a person, and cancelable by
   a state actor. There is no EU-sovereign alternative in wide deployment.

2. **IP addresses are visible to relay operators.** Even with end-to-end encryption,
   the communication graph — who talks to whom, when, how often — is fully visible to
   infrastructure operators. This metadata is frequently more valuable to an adversary
   than message content.

> **Status (Sep 2026):** Hiding IP addresses (done, via Tor) does not hide the graph by itself. FURY's graph
> is currently keyed by long-term pubkeys, which are visible in every event. These are two
> separate problems with two separate fixes: M3 (Tor) is done, M3.5 (gift wrap) is not started.

3. **Infrastructure is centralised and seizable.** A single legal order, server seizure,
   or corporate policy change can silence an entire user base. No architectural mitigation
   exists in any widely-deployed messenger today.

4. **Cryptographic identity is not portable.** Users cannot migrate their identity between
   clients without losing their contact graph, message history, or group memberships.
   Vendor lock-in is structural, not incidental.

**FURY** addresses all four failure modes in a single, open-source, pure-Rust implementation:
phone-number-free identity derived from a user-controlled BIP-39 mnemonic; mandatory IP
anonymisation via embedded Tor (no external daemon, ships inside the binary); decentralised
relay infrastructure via the open Nostr protocol (thousands of independently-operated relays,
no single point of seizure); and cryptographic identity fully portable across any
NIP-06-compliant client.

> **Status (Sep 2026):** What exists today, per failure mode:
> 1. Phone-number-free identity from a mnemonic: **done** (M0, NIP-06 vectors).
> 2. IP anonymisation: **done** (M3). The communication graph is **not** protected yet (M3.5).
> 3. Decentralised relays: **done**. Any Nostr relay works.
> 4. Portability: the **identity key** is portable across NIP-06 clients. **Messages are not**:
>    FURY puts NIP-44 content in kind-4 events, where other clients expect NIP-04, so they
>    can't read FURY DMs until M3.5 moves them to NIP-17. There is no contact list or history
>    export yet.

---

## Why not SimpleX?

SimpleX Chat is the strongest existing answer to the metadata problem, and FURY does not claim
to beat it there. The two projects answer different needs.

### Where SimpleX is ahead today

- **No user identifiers at all.** Not even random ones. Each contact pair talks through its own
  one-way message queues, each on a server chosen by the receiving side. FURY's design leaks
  more by construction:
  - even with gift-wrapped DMs (NIP-17), the recipient's inbox relay sees the recipient's
    pubkey and when each message for it arrives;
  - NIP-17 also stores a copy for the sender on the sender's own relays, tagged with the
    sender's pubkey;
  - a relay that requires AUTH before accepting messages learns who is writing.

  SimpleX's protection isn't absolute either. A SimpleX server can link a user's queues that
  are accessed over the same connection, and by default that's one connection per chat profile.
- **It ships.**
  - Apps for iOS, Android, desktop and the terminal.
  - Post-quantum key exchange (sntrup761) in the double ratchet: on by default for direct
    chats since v5.7 (April 2024).
  - Two-hop private message routing, on by default since v6.0 (August 2024).
  - Two Trail of Bits reviews: an implementation assessment (2022) and a cryptographic design
    review (2024).
  - Self-hostable servers.

For contact between a journalist and a source, where nobody should be able to link the two,
SimpleX is the better tool today.

### What SimpleX doesn't do, and FURY targets

1. **A recoverable, verifiable identity.** SimpleX has no account and no recovery by design.
   "Migrate to another device" and database export move the app's data, but a lost device
   without a recent export means lost contacts. FURY's identity is a key derived from 12
   words: it can be restored on any device, and contacts can verify it's the same person. An
   organisation needs this to onboard and offboard members, confirm who is who, replace a lost
   phone, and remove a compromised device.
2. **Large end-to-end encrypted groups.**
   - SimpleX groups are pairwise: every message goes to every member over its own connection.
     SimpleX's own docs say this can't scale to large audiences. Post-quantum encryption isn't
     used in groups yet.
   - Channels (v6.5, April 2026) scale through chat relays, but their content isn't end-to-end
     encrypted to the relays.
   - FURY plans MLS (RFC 9420), where the cost of key updates grows logarithmically with group
     size.
3. **Tor built in.** SimpleX relies on an external Tor proxy: Orbot on Android and iOS, or a
   local SOCKS proxy on desktop. Its private routing hides the sender's IP from the
   recipient's server, but not from the forwarding server the sender connects to. FURY sends
   every relay connection through embedded Tor (Arti), with nothing to install.
4. **An open network.** Nostr has thousands of independently run relays and many clients.
   SimpleX's preset servers are run by two operators, SimpleX Chat Ltd and Flux. Anyone can
   self-host, but it remains one protocol with one family of apps.
5. **Jurisdiction.** SimpleX Chat Ltd is registered in the UK, which is outside the EU. Its
   servers can be self-hosted, so the remaining dependency is the software publisher and, on
   iOS, push notifications, which go only through SimpleX Chat Ltd. That iOS constraint applies
   to any iOS app: FURY's planned push proxy (M5.5) would be the same kind of operator.

### Positioning

**SimpleX gives individuals anonymity, from servers and from each other. FURY gives an
organisation's members identities that are verifiable and recoverable, with no central
provider**, together with metadata protection that is good enough in practice: Tor for IP
addresses, gift wrap to hide senders, and inbox relays the organisation runs itself.

**The organisation's own relays are what close the remaining gap.** An inbox relay has to see
the recipient's pubkey when a message arrives, and hold the message until the recipient fetches
it. That's inherent to store-and-forward delivery. What an organisation can control is who
that relay is:
- FURY clients can be configured to use only the organisation's relays, and to refuse all
  others.
- Those relays can delete each message once it's delivered and keep no logs, so there is
  nothing to seize or subpoena later.
- With Tor in front, the relay doesn't learn members' IP addresses either.

That leaves the metadata observer inside the organisation's own trust boundary rather than
with a third party. It's a matter of operator policy, which the protocol can't enforce, but
the organisation is the operator.

> **Option for later: rotating inbox tags instead of the recipient's pubkey.** Today every
> gift-wrapped message names its recipient in a `p` tag, which is what the inbox relay sees.
> SECURITY.md's pairwise receiving keys (mitigation step 5) replace that pubkey with a fixed
> pseudonym per contact, which a relay can still follow over time. Rotating tags go one step
> further: each pair of contacts derives a tag from the key they already share for NIP-44
> encryption. For example, `tag = HKDF(conversation_key, "fury-inbox" ‖ epoch)`, with a new
> epoch every day. The sender addresses the message to that tag, and the recipient subscribes to
> the current tag of each contact. The relay then sees opaque tags that change every epoch,
> which it can't connect to a pubkey or to earlier epochs. It would no longer need to see the
> recipient's pubkey at all, even at delivery.
>
> The trade-offs:
> - **Interoperability:** other NIP-17 clients look for the `p` tag, so this only works between
>   FURY clients. Messages to other clients would still use standard NIP-17.
> - **First contact:** a sender the recipient doesn't know yet has no shared tag to use, so the
>   first message still needs the recipient's pubkey. After that the contacts switch to tags.
> - **Subscriptions:** a recipient subscribes to one tag per contact. If it fetches them all over
>   one connection, the relay can link them together. Separate Tor circuits, or spreading the
>   fetches out, reduce that.
> - **Read access:** a relay can't restrict reads to the recipient by pubkey (NIP-42 AUTH)
>   anymore. Knowing the tag becomes the permission to read, which is acceptable because tags
>   can't be guessed and the content is encrypted anyway.

> **Status (Sep 2026):** FURY's side of this comparison is mostly planned. Tor transport (M3)
> is done. Gift-wrapped DMs (M3.5), MLS groups (M5) and the mobile apps (M9) are not started.
> Clients restricted to an organisation's relays, and a relay that deletes messages on
> delivery, are not built either. The self-hosted relay package is Phase 3.
> SimpleX facts are as of app v7.0.3 (September 2026), checked against its repositories, docs
> and release notes.

---

## Development Roadmap

### Phase 1 — Protocol Foundation & Identity CLI

**Scope:** Complete the cryptographic and networking core; deliver a usable identity
management CLI.

**Delivers:**
- `fury-core` — headless Rust library: BIP-39/BIP-32 identity, NIP-44 v2 end-to-end
  encryption, NIP-01 Nostr event layer, embedded Tor transport via Arti (no daemon),
  NIP-17 / NIP-59 gift-wrapped direct messages that hide the sender from relays, with
  AUTH-protected inbox relays, encrypted at-rest mnemonic storage (Argon2id + ChaCha20-Poly1305), MLS group messaging
  (RFC 9420, via `openmls`), contentless push notifications (APNs/FCM + UnifiedPush).

> **Status (Sep 2026):** **Done:** BIP-39/BIP-32 identity, NIP-44 v2, NIP-01 events, Arti Tor transport.
> **Not started:** gift-wrapped DMs (M3.5), at-rest storage (M4), MLS (M5), push (M5.5).
- `fury-sign` CLI — `generate`, `show`, `import` subcommands for identity lifecycle
  management. No private key material ever leaves the device unencrypted.

> **Status (Sep 2026):** `fury-sign` is an empty stub. Today the only way to load keys is the demo's
> `FURY_MNEMONIC` environment variable. That puts the mnemonic in plaintext in the shell
> environment and possibly in shell history, so this guarantee applies only once M4/M7 land.
- Full integration test suite: two-node message round-trip through embedded Tor, MLS group
  round-trip, encrypted storage save/load, all validated against published protocol test vectors.

> **Status (Sep 2026):** NIP-06 and NIP-44 official vectors pass. The two-node Tor round-trip, MLS and storage
> tests don't exist yet (M6).

**Properties at phase end:** a complete, auditable protocol implementation usable from the
command line, with no dependency on any US-operated or proprietary infrastructure.

> **Status (Sep 2026):** Two caveats. **APNs/FCM** in this phase's own scope are US-operated (Apple/Google);
> only UnifiedPush avoids them. **Tor** is developed by the Tor Project, a US non-profit,
> though the network itself is run by independent relay operators worldwide.

---

### Phase 2 — End-User Applications

**Scope:** Expose `fury-core` to non-technical users on desktop and mobile via thin
platform shells. The cryptographic and networking stack is unchanged — only the UI layer
is added.

**Delivers:**
- `fury-desktop` — cross-platform GUI (macOS, Linux, Windows) via Tauri. Rust backend,
  minimal web frontend, no Electron, no telemetry, no external asset loads. Full Tor
  bootstrap and relay I/O runs inside the Tauri async runtime.
- `fury-android` / `fury-ios` — native mobile apps via UniFFI (Mozilla's production-grade
  Rust → Kotlin/Swift bridge, used in Firefox for Android and Mozilla VPN). Platform shells
  handle UI and OS integration (push tokens, Keychain/Keystore, background fetch);
  all cryptography and transport runs in `fury-core` without modification.
- UnifiedPush as default on de-Googled Android (GrapheneOS, CalyxOS), eliminating
  the Apple/Google intermediary from the push delivery path entirely.

**Properties at phase end:** a complete, sovereign communication stack deployable by
individual users on all major platforms, with no account registration and no exposure of
IP addresses or communication metadata to any third party.

> **Status (Sep 2026):** Phase 2 hasn't started. Even when complete, some metadata still reaches third parties:
> APNs/FCM see push timing (SECURITY.md → Known Limitations), and the recipient's inbox relay
> sees when wrapped messages arrive. Only UnifiedPush plus a self-hosted inbox relay removes both.

---

### Phase 3 — Organisational Deployment

**Scope:** Build the tooling and operational harness necessary for structured deployment
within organisations — diplomatic missions, civil society groups, investigative newsrooms,
public sector bodies — without reintroducing centralisation.

**Delivers:**
- **Group provisioning tooling** — CLI and API for managing MLS group membership at
  organisational scale: onboard members, rotate keys, remove compromised devices. All
  operations are cryptographic; no server holds keys or group state.
- **Self-hosted relay package** — hardened, single-binary Nostr relay with operational
  documentation for air-gapped or restricted-network deployment.
- **Audit trail layer** — metadata-minimal event log sufficient for organisational
  compliance requirements (message delivery confirmation, group membership changes),
  implemented as Nostr events so the audit trail itself is decentralised and portable.

> **Status (Sep 2026):** Not started. Audit events published to relays would themselves be metadata. They
> must be encrypted and gift-wrapped, and go to access-controlled relays, or they recreate the
> graph leak.
- **Protocol bridge adapters** — integration connectors for existing organisational
  communication infrastructure (Matrix federation, XMPP), enabling incremental migration
  without requiring a hard cutover.
- **Deployment documentation** — operational security guide for high-risk environments:
  network isolation, device provisioning, key ceremony procedures, incident response.

**Properties at phase end:** a complete sovereign communication stack deployable by
organisations in hostile-jurisdiction environments, with no dependency on any external
service provider and no single point of administrative control, seizure, or compulsion.
