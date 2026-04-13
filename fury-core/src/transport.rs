use std::sync::Arc;

use arti_client::{TorClient, TorClientConfig};
use async_tungstenite::tungstenite::Message;
use futures::stream::BoxStream;
use futures::{SinkExt, StreamExt};
use serde_json::json;
use tokio::sync::{broadcast, mpsc};
use tor_rtcompat::PreferredRuntime;

use crate::error::{FuryError, FuryResult};
use crate::event::NostrEvent;

/// Bootstrap an in-process Tor client.  Call once at startup; share via `Arc`.
///
/// First call takes ~5–10 s while Arti downloads the Tor consensus and builds
/// circuits.  Subsequent runs reuse the on-disk cache (`~/.local/share/arti`).
pub async fn bootstrap_tor() -> FuryResult<TorClient<PreferredRuntime>> {
    TorClient::create_bootstrapped(TorClientConfig::default())
        .await
        .map_err(|e| FuryError::Network(e.to_string()))
}

/// Filter for a Nostr REQ subscription.
pub struct SubscriptionFilter {
    pub authors: Vec<String>,
    pub kinds: Vec<u16>,
    /// Hex pubkeys for the `#p` tag filter.
    pub p_tags: Vec<String>,
    pub since: Option<u64>,
    pub limit: Option<u32>,
}

impl SubscriptionFilter {
    fn to_json(&self) -> serde_json::Value {
        let mut f = serde_json::Map::new();
        if !self.authors.is_empty() {
            f.insert("authors".into(), json!(self.authors));
        }
        if !self.kinds.is_empty() {
            f.insert("kinds".into(), json!(self.kinds));
        }
        if !self.p_tags.is_empty() {
            f.insert("#p".into(), json!(self.p_tags));
        }
        if let Some(since) = self.since {
            f.insert("since".into(), json!(since));
        }
        if let Some(limit) = self.limit {
            f.insert("limit".into(), json!(limit));
        }
        serde_json::Value::Object(f)
    }
}

/// A Nostr relay connection routed through Tor.
///
/// Internally runs a background task that owns the WebSocket and multiplexes
/// frames via channels.  `publish` and `subscribe` share the same connection
/// concurrently without any external locking.
///
/// # Privacy invariant
/// The only constructor is [`RelayClient::connect`], which requires a
/// `TorClient`.  There is no `connect_direct()`.
pub struct RelayClient {
    outbound: mpsc::Sender<String>,
    inbound: broadcast::Sender<String>,
}

impl RelayClient {
    /// Open a WebSocket connection to `relay_url` through the given Tor client.
    pub async fn connect(
        relay_url: &str,
        tor: Arc<TorClient<PreferredRuntime>>,
    ) -> FuryResult<Self> {
        use url::Url;
        let url = Url::parse(relay_url).map_err(|e| FuryError::Network(e.to_string()))?;

        let host = url
            .host_str()
            .ok_or_else(|| FuryError::Network("relay URL missing host".into()))?
            .to_owned();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| FuryError::Network("relay URL missing port".into()))?;

        let mut tor_stream = tor
            .connect((host.as_str(), port))
            .await
            .map_err(|e| FuryError::Network(format!("Tor connect: {e}")))?;

        // Wait for the Tor stream to be fully connected before attempting WebSocket handshake
        tor_stream
            .wait_for_connection()
            .await
            .map_err(|e| FuryError::Network(format!("Tor stream not ready: {e}")))?;

        let (ws, _) = async_tungstenite::tokio::client_async_tls(relay_url, tor_stream)
            .await
            .map_err(|e| FuryError::Network(format!("WebSocket handshake: {e}")))?;

        let (mut sink, mut stream) = ws.split();
        let (out_tx, mut out_rx) = mpsc::channel::<String>(32);
        let (in_tx, _) = broadcast::channel::<String>(128);
        let in_tx2 = in_tx.clone();

        // Background task: owns the WebSocket halves; bridges channels ↔ wire.
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(frame) = out_rx.recv() => {
                        if sink.send(Message::Text(frame)).await.is_err() {
                            break;
                        }
                    }
                    msg = stream.next() => {
                        match msg {
                            Some(Ok(Message::Text(t))) => {
                                // Ignore send errors: no active receivers is fine.
                                let _ = in_tx2.send(t.to_string());
                            }
                            Some(Ok(Message::Close(_))) | None => break,
                            Some(Err(_)) => break,
                            _ => {}
                        }
                    }
                }
            }
        });

        Ok(Self {
            outbound: out_tx,
            inbound: in_tx,
        })
    }

    /// Publish a signed NIP-01 event: sends `["EVENT", event]` to the relay.
    pub async fn publish(&self, event: &NostrEvent) -> FuryResult<()> {
        let frame = serde_json::to_string(&json!(["EVENT", event]))
            .map_err(|e| FuryError::Network(e.to_string()))?;
        self.outbound
            .send(frame)
            .await
            .map_err(|_| FuryError::Network("relay task dropped".into()))
    }

    /// Subscribe to events matching `filter`.
    ///
    /// Sends the `REQ` frame immediately, then returns a stream that yields
    /// decoded `NostrEvent`s as the relay delivers them.  Non-EVENT frames
    /// (EOSE, NOTICE, OK) are not yielded; use [`RelayClient::raw_frames`] to
    /// observe those.
    pub async fn subscribe(
        &self,
        sub_id: impl Into<String>,
        filter: SubscriptionFilter,
    ) -> FuryResult<BoxStream<'static, FuryResult<NostrEvent>>> {
        let sub_id = sub_id.into();
        let frame = serde_json::to_string(&json!(["REQ", sub_id, filter.to_json()]))
            .map_err(|e| FuryError::Network(e.to_string()))?;
        self.outbound
            .send(frame)
            .await
            .map_err(|_| FuryError::Network("relay task dropped".into()))?;

        let rx = self.inbound.subscribe();

        Ok(Box::pin(futures::stream::unfold(
            (rx, sub_id),
            |(mut rx, sub_id)| async move {
                loop {
                    match rx.recv().await {
                        Ok(text) => {
                            let v: serde_json::Value = match serde_json::from_str(&text) {
                                Ok(v) => v,
                                Err(_) => continue,
                            };
                            if v[0].as_str() != Some("EVENT") {
                                continue;
                            }
                            if v[1].as_str() != Some(sub_id.as_str()) {
                                continue;
                            }
                            let result = serde_json::from_value::<NostrEvent>(v[2].clone())
                                .map_err(|e| FuryError::Network(e.to_string()));
                            return Some((result, (rx, sub_id)));
                        }
                        Err(broadcast::error::RecvError::Closed) => return None,
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    }
                }
            },
        )))
    }

    /// Returns a receiver for raw JSON frames from the relay (EOSE, NOTICE,
    /// OK, EVENT, …).  Useful for logging relay status messages.
    pub fn raw_frames(&self) -> broadcast::Receiver<String> {
        self.inbound.subscribe()
    }
}
