# FURY — Sovereign Communication Stack
## Problem Statement & Development Roadmap

---

## The Problem

Secure communication is critical infrastructure. Yet every widely-deployed encrypted messenger
today depends on infrastructure or corporate entities subject to non-European jurisdiction:

- **Signal** is a US non-profit, incorporated under US law, subpoenable by US courts, and
  requires a phone number — a government-issued, telecom-linked identifier — to register.
- **WhatsApp** is owned by Meta, a US corporation with a documented history of bulk metadata
  collection and legal compliance with US intelligence requests.
- **Matrix** improves decentralisation but still routes most traffic through `matrix.org`,
  a UK-incorporated entity, and does not address IP-level metadata exposure.

The consequences are concrete. Journalists communicating with sources in authoritarian states,
diplomats operating in hostile-jurisdiction countries, civil society organisations working
under surveillance, and public servants handling sensitive policy discussions are all
currently forced to choose between convenience and genuine operational security — with no
European-sovereign alternative that meets professional-grade requirements.

## Who Needs This Today

**EU diplomatic staff in hostile-jurisdiction countries** are the clearest case. An embassy
employee in a country with active signal intelligence capabilities — coordinating with local
contacts, exchanging operational assessments, or simply arranging logistics — currently has
no sovereign option. Signal is US-incorporated and phone-number-linked: a local SIM card
issued under a real-name registration regime is an identity anchor, not a pseudonym.
WhatsApp is Meta. Classified channels do not cover day-to-day coordination. The gap between
"classified" and "plaintext email" is where operational security breaks down in practice,
and it is currently filled by US-controlled commercial software.

**Investigative journalists** working cross-border face the same gap from a different angle.
A journalist communicating with a source inside an authoritarian state needs deniable
contact — not just encrypted content, but no communication graph. Who talked to whom,
when, and how often is often more damaging than message content. No widely-deployed
messenger hides this metadata by default.

**Civil society organisations** operating in restricted jurisdictions — human rights monitors,
election observers, legal aid networks — face coordinated infrastructure attacks and legal
pressure on their communication providers. A tool with no central operator to subpoena and
no IP addresses visible to relay operators removes the two most common attack vectors.

**Public sector teams handling sensitive policy** — procurement officers, negotiators,
regulators — increasingly operate across borders and devices without access to classified
infrastructure, yet deal with information that is commercially or politically sensitive.
Consumer messengers are the de-facto standard. That is the actual threat surface.

In all four cases the requirement is the same: communication that leaves no exploitable
metadata trail, runs on no infrastructure that a hostile actor can seize or subpoena,
and requires no identity anchor beyond a key the user controls.

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

---

## Development Roadmap

### Phase 1 — Protocol Foundation & Identity CLI

**Scope:** Complete the cryptographic and networking core; deliver a usable identity
management CLI.

**Delivers:**
- `fury-core` — headless Rust library: BIP-39/BIP-32 identity, NIP-44 v2 end-to-end
  encryption, NIP-01 Nostr event layer, embedded Tor transport via Arti (no daemon),
  encrypted at-rest mnemonic storage (Argon2id + ChaCha20-Poly1305), MLS group messaging
  (RFC 9420, via `openmls`), contentless push notifications (APNs/FCM + UnifiedPush).
- `fury-sign` CLI — `generate`, `show`, `import` subcommands for identity lifecycle
  management. No private key material ever leaves the device unencrypted.
- Full integration test suite: two-node message round-trip through embedded Tor, MLS group
  round-trip, encrypted storage save/load, all validated against published protocol test vectors.

**Properties at phase end:** a complete, auditable protocol implementation usable from the
command line, with no dependency on any US-operated or proprietary infrastructure.

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
- **Protocol bridge adapters** — integration connectors for existing organisational
  communication infrastructure (Matrix federation, XMPP), enabling incremental migration
  without requiring a hard cutover.
- **Deployment documentation** — operational security guide for high-risk environments:
  network isolation, device provisioning, key ceremony procedures, incident response.

**Properties at phase end:** a complete sovereign communication stack deployable by
organisations in hostile-jurisdiction environments, with no dependency on any external
service provider and no single point of administrative control, seizure, or compulsion.
