use crate::error::{FuryError, FuryResult};
use crate::identity::FuryIdentity;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::schnorr::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A signed NIP-01 Nostr event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrEvent {
    pub id: String,      // hex SHA-256 of canonical serialization
    pub pubkey: String,  // hex xonly pubkey
    pub created_at: u64, // unix timestamp (seconds)
    pub kind: u16,       // 1 = text note, 44 = NIP-44 DM, ...
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String, // hex BIP-340 Schnorr signature (64 bytes)
}

impl NostrEvent {
    /// Build and sign a NIP-01 event.
    ///
    /// `kind: 1` is a plain text note. The event ID and signature are computed
    /// automatically.
    pub fn sign(
        identity: &FuryIdentity,
        kind: u16,
        tags: Vec<Vec<String>>,
        content: String,
    ) -> FuryResult<Self> {
        let pubkey = identity.pubkey_hex();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let id_bytes = Self::compute_id(&pubkey, created_at, kind, &tags, &content)?;
        let sig = identity.sign(&id_bytes)?;

        Ok(Self {
            id: hex::encode(id_bytes),
            pubkey,
            created_at,
            kind,
            tags,
            content,
            sig: hex::encode(sig.to_bytes()),
        })
    }

    /// Verify the event ID and BIP-340 Schnorr signature.
    pub fn verify(&self) -> FuryResult<()> {
        // 1. Recompute event ID from fields
        let expected = Self::compute_id(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        )?;

        if hex::encode(expected) != self.id {
            return Err(FuryError::Internal("Event ID mismatch".into()));
        }

        // 2. Decode pubkey (32-byte xonly)
        let pubkey_bytes: [u8; 32] = hex::decode(&self.pubkey)
            .map_err(|_| FuryError::Internal("Invalid pubkey hex".into()))?
            .try_into()
            .map_err(|_| FuryError::Internal("Pubkey must be 32 bytes".into()))?;
        let pubkey = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|_| FuryError::Internal("Invalid pubkey".into()))?;

        // 3. Decode signature (64 bytes)
        let sig_bytes: [u8; 64] = hex::decode(&self.sig)
            .map_err(|_| FuryError::Internal("Invalid sig hex".into()))?
            .try_into()
            .map_err(|_| FuryError::Internal("Signature must be 64 bytes".into()))?;
        let sig = Signature::try_from(sig_bytes.as_slice())
            .map_err(|_| FuryError::Internal("Invalid signature bytes".into()))?;

        // 4. Verify signature against event ID
        pubkey.verify_prehash(&expected, &sig)?;
        Ok(())
    }

    /// NIP-01 canonical serialization for ID computation:
    /// [0, pubkey_hex, created_at, kind, tags, content]
    fn compute_id(
        pubkey: &str,
        created_at: u64,
        kind: u16,
        tags: &[Vec<String>],
        content: &str,
    ) -> FuryResult<[u8; 32]> {
        let canonical = serde_json::json!([0, pubkey, created_at, kind, tags, content]);
        let bytes =
            serde_json::to_vec(&canonical).map_err(|e| FuryError::Internal(e.to_string()))?;
        Ok(Sha256::digest(&bytes).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::FuryIdentity;
    use secrecy::SecretString;

    fn test_identity() -> FuryIdentity {
        FuryIdentity::new(SecretString::new(
            "leader monkey parrot ring guide accident before fence cannon height naive bean".into(),
        ))
        .unwrap()
    }

    #[test]
    fn sign_and_verify() {
        let identity = test_identity();
        let event = NostrEvent::sign(&identity, 1, vec![], "hello fury".into()).unwrap();
        event.verify().unwrap();
    }

    #[test]
    fn tampered_content_fails_verify() {
        let identity = test_identity();
        let mut event = NostrEvent::sign(&identity, 1, vec![], "hello fury".into()).unwrap();
        event.content = "tampered".into();
        assert!(event.verify().is_err());
    }

    #[test]
    fn tampered_sig_fails_verify() {
        let identity = test_identity();
        let mut event = NostrEvent::sign(&identity, 1, vec![], "hello fury".into()).unwrap();
        // Flip the last character of the hex signature
        let last = event.sig.pop().unwrap();
        event.sig.push(if last == 'f' { '0' } else { 'f' });
        assert!(event.verify().is_err());
    }

    #[test]
    fn event_id_is_64_hex_chars() {
        let identity = test_identity();
        let event = NostrEvent::sign(&identity, 1, vec![], "test".into()).unwrap();
        assert_eq!(event.id.len(), 64);
    }

    #[test]
    fn sig_is_128_hex_chars() {
        let identity = test_identity();
        let event = NostrEvent::sign(&identity, 1, vec![], "test".into()).unwrap();
        assert_eq!(event.sig.len(), 128); // 64 bytes * 2
    }
}
