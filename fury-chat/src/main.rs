use std::sync::Arc;

use anyhow::{Context, Result};
use futures::StreamExt;
use secrecy::SecretString;
use tokio::io::AsyncBufReadExt;

use fury_core::event::NostrEvent;
use fury_core::identity::FuryIdentity;
use fury_core::nip44;
use fury_core::transport::{RelayClient, SubscriptionFilter};

/*

FURY_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
cargo run -p fury-chat -- --print-pubkey
e8bcf3823669444d0b49ad45d65088635d9fd8500a75b5f20b59abefa56a144f

FURY_MNEMONIC="leader monkey parrot ring guide accident before fence cannon height naive bean" \
cargo run -p fury-chat -- --print-pubkey
17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917

---

# Terminal A

FURY_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
FURY_RECIPIENT="17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917" \
FURY_RELAY="wss://nos.lol" \
cargo run -p fury-chat

---

# Terminal B

FURY_MNEMONIC="leader monkey parrot ring guide accident before fence cannon height naive bean" \
FURY_RECIPIENT="e8bcf3823669444d0b49ad45d65088635d9fd8500a75b5f20b59abefa56a144f" \
FURY_RELAY="wss://nos.lol" \
cargo run -p fury-chat

*/

const PRINT_PUBKEY: &str = "--print-pubkey";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let mnemonic =
        std::env::var("FURY_MNEMONIC").context("Set FURY_MNEMONIC to a BIP-39 mnemonic")?;

    let identity =
        FuryIdentity::new(SecretString::new(mnemonic)).context("Failed to derive identity")?;
    let our_pubkey = identity.pubkey_hex();

    eprintln!("your pubkey  : {our_pubkey}");

    let print_pubkey = std::env::args().any(|arg| arg == PRINT_PUBKEY);
    if print_pubkey {
        return Ok(());
    }

    let relay_url = std::env::var("FURY_RELAY").unwrap_or_else(|_| "wss://relay.damus.io".into());
    let recipient_pubkey = match std::env::var("FURY_RECIPIENT") {
        Ok(v) => v,
        Err(_) => {
            eprintln!();
            eprintln!("Share the pubkey above with your peer, then restart with:");
            eprintln!("  FURY_RECIPIENT=<peer_pubkey_hex> ...");
            return Ok(());
        }
    };

    let conv_key = nip44::conversation_key(&identity, &recipient_pubkey)
        .context("Failed to derive conversation key")?;

    eprintln!("peer pubkey  : {recipient_pubkey}");
    eprintln!("relay        : {relay_url}");
    eprintln!("bootstrapping Tor (first run ~10 s) ...");

    let tor = Arc::new(
        fury_core::transport::bootstrap_tor()
            .await
            .context("Tor bootstrap failed")?,
    );

    let relay = RelayClient::connect(&relay_url, tor)
        .await
        .context("Failed to connect to relay")?;

    eprintln!("---  type a message and press Enter  ---");

    // Log relay status frames (EOSE, NOTICE, OK) without blocking the event stream.
    let mut raw = relay.raw_frames();
    tokio::spawn(async move {
        while let Ok(text) = raw.recv().await {
            let v: serde_json::Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(_) => continue,
            };
            match v[0].as_str() {
                Some("EOSE") => eprintln!("[relay: caught up with stored history]"),
                Some("NOTICE") => eprintln!("[relay notice]: {}", v[1]),
                Some("OK") if !v[2].as_bool().unwrap_or(false) => {
                    eprintln!("[relay: message rejected — {}]", v[3]);
                }
                _ => {}
            }
        }
    });

    // Subscribe to kind:4 events sent from the peer to us.
    let filter = SubscriptionFilter {
        authors: vec![recipient_pubkey.clone()],
        kinds: vec![4],
        p_tags: vec![our_pubkey.clone()],
        since: None,
        limit: None,
    };
    let mut events = relay
        .subscribe("fury-chat", filter)
        .await
        .context("Failed to subscribe")?;

    // Receive task: decrypt and print incoming messages.
    let conv_key_recv = conv_key;
    tokio::spawn(async move {
        while let Some(result) = events.next().await {
            let event: NostrEvent = match result {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("[error]: {e}");
                    continue;
                }
            };
            if let Ok(plaintext) = nip44::decrypt(&conv_key_recv, &event.content) {
                println!("[{:.8}]: {plaintext}", event.pubkey)
            }
        }
    });

    // Stdin loop: read lines, encrypt, publish.
    let stdin = tokio::io::stdin();
    let mut lines = tokio::io::BufReader::new(stdin).lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_owned();
        if line.is_empty() {
            continue;
        }

        let encrypted = nip44::encrypt(&conv_key, &line).context("Encryption failed")?;

        let event = NostrEvent::sign(
            &identity,
            4,
            vec![vec!["p".into(), recipient_pubkey.clone()]],
            encrypted,
        )
        .context("Failed to sign event")?;

        relay.publish(&event).await.context("Failed to publish")?;
        println!("[you]: {line}");
    }

    Ok(())
}
