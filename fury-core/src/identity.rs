use crate::error::{FuryError, FuryResult};
use bech32::{ToBase32, Variant};
use bip32::{DerivationPath, XPrv};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::schnorr::{Signature, SigningKey};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroize;

const NOSTR_PATH: &str = "m/44'/1237'/0'/0/0";

pub enum CoinType {
    Ethereum,
    Bitcoin,
}

impl CoinType {
    fn path(&self) -> &'static str {
        match self {
            CoinType::Ethereum => "m/44'/60'/0'/0/0",
            CoinType::Bitcoin => "m/44'/0'/0'/0/0",
        }
    }
}

/// A BIP-44 wallet key (EVM or BTC), mlock-protected and zeroized on drop.
pub struct WalletKey {
    key_bytes: Box<[u8; 32]>,
}

impl WalletKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        *self.key_bytes
    }
}

impl Drop for WalletKey {
    fn drop(&mut self) {
        unsafe {
            memsec::munlock(self.key_bytes.as_ref().as_ptr() as *mut _, 32);
        }
        self.key_bytes.zeroize();
    }
}

/// Derive an EVM or BTC wallet key from a BIP-39 mnemonic at the standard BIP-44 path.
pub fn derive_wallet_key(mnemonic: SecretString, coin: CoinType) -> FuryResult<WalletKey> {
    let mut raw: [u8; 32] = {
        let phrase = mnemonic.expose_secret();
        let mnemonic_obj = bip39::Mnemonic::parse(phrase)?;
        let seed = mnemonic_obj.to_seed("");
        let path: DerivationPath = coin.path().parse()?;
        let child = XPrv::derive_from_path(seed, &path)?;
        child.private_key().to_bytes().into()
    };

    let key_bytes = Box::new(raw);
    raw.zeroize();

    let locked = unsafe { memsec::mlock(key_bytes.as_ref().as_ptr() as *mut _, 32) };
    if !locked {
        return Err(FuryError::HardwareLock);
    }

    Ok(WalletKey { key_bytes })
}

/// A Nostr-compatible secp256k1 identity backed by a BIP-39 mnemonic.
///
/// The private key scalar is:
///   - heap-allocated (not on the stack, address is stable)
///   - memory-locked via mlock(2) (OS will not swap it to disk)
///   - zeroized on drop
///
/// The `SigningKey` is never stored — it is reconstructed from the locked
/// bytes on each `sign` call and immediately dropped. This minimises the
/// window during which key material exists in unlocked register/cache state.
pub struct FuryIdentity {
    key_bytes: Box<[u8; 32]>,
}

impl FuryIdentity {
    /// Derive a Nostr identity from a BIP-39 mnemonic via NIP-06.
    ///
    /// Returns `FuryError::HardwareLock` if the OS refuses to lock the
    /// memory page (e.g. hard rlimit on locked pages).
    pub fn new(mnemonic: SecretString) -> FuryResult<Self> {
        let mut raw: [u8; 32] = {
            let phrase = mnemonic.expose_secret();
            let mnemonic_obj = bip39::Mnemonic::parse(phrase)?;

            // 512-bit BIP-39 seed — never stored, lives only in this scope
            let seed = mnemonic_obj.to_seed("");

            // NIP-06: derive child key at m/44'/1237'/0'/0/0
            let path: DerivationPath = NOSTR_PATH.parse()?;
            let child = XPrv::derive_from_path(seed, &path)?;

            // bip32 gives us a k256 ECDSA key; the underlying scalar is the
            // same 32 bytes used for BIP-340 Schnorr — only the signing
            // algorithm differs.
            child.private_key().to_bytes().into()
        };

        // Validate the scalar is in-range for BIP-340 before we commit to it
        SigningKey::from_bytes(&raw).map_err(|_| {
            FuryError::Internal("Derived scalar is invalid for BIP-340 Schnorr".into())
        })?;

        let key_bytes = Box::new(raw);
        raw.zeroize(); // scrub stack copy

        // Lock the heap page — kernel will not include it in swap or core dumps
        let locked = unsafe { memsec::mlock(key_bytes.as_ref().as_ptr() as *mut _, 32) };
        if !locked {
            return Err(FuryError::HardwareLock);
        }

        Ok(Self { key_bytes })
    }

    /// The xonly (32-byte) Nostr public key derived from this identity.
    pub fn nostr_pubkey(&self) -> k256::schnorr::VerifyingKey {
        // Safety: key_bytes were validated in new() before being stored
        *SigningKey::from_bytes(self.key_bytes.as_ref())
            .expect("key_bytes are always valid — validated on construction")
            .verifying_key()
    }

    /// Hex-encoded xonly public key — the standard representation in NIP-01 events.
    pub fn pubkey_hex(&self) -> String {
        hex::encode(self.nostr_pubkey().to_bytes())
    }

    /// NIP-19 bech32-encoded public key (npub1…).
    pub fn npub(&self) -> String {
        let bytes = self.nostr_pubkey().to_bytes();
        bech32::encode("npub", bytes.to_base32(), Variant::Bech32)
            .expect("npub encoding is infallible")
    }

    /// Raw ECDH shared secret (x-coordinate of shared secp256k1 point).
    ///
    /// The recipient is identified by their 32-byte x-only Nostr public key (hex).
    /// The even-Y convention (BIP-340) is applied when reconstructing the full point.
    ///
    /// The returned bytes are the IKM for NIP-44 conversation key derivation;
    /// use `nip44::conversation_key()` rather than calling this directly.
    pub fn ecdh_shared_secret(&self, recipient_pubkey_hex: &str) -> FuryResult<[u8; 32]> {
        use k256::{PublicKey, SecretKey};

        let pubkey_bytes = hex::decode(recipient_pubkey_hex)
            .map_err(|_| FuryError::Internal("Invalid recipient pubkey hex".into()))?;
        if pubkey_bytes.len() != 32 {
            return Err(FuryError::Internal(
                "Recipient pubkey must be 32 bytes".into(),
            ));
        }

        // BIP-340 x-only pubkey → compressed SEC1 point with even Y (prefix 0x02)
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(&pubkey_bytes);

        let recipient_pk = PublicKey::from_sec1_bytes(&compressed).map_err(FuryError::Crypto)?;
        let our_sk = SecretKey::from_slice(self.key_bytes.as_ref()).map_err(FuryError::Crypto)?;

        let scalar = our_sk.to_nonzero_scalar();
        let shared = k256::ecdh::diffie_hellman(&scalar, recipient_pk.as_affine());

        let mut result = [0u8; 32];
        result.copy_from_slice(&shared.raw_secret_bytes()[..]);
        Ok(result)
    }

    /// Sign a 32-byte pre-hashed message using BIP-340 Schnorr.
    ///
    /// For Nostr events, `message` is the SHA-256 of the canonical event JSON
    /// (the NIP-01 event ID). The `SigningKey` is reconstructed for this call
    /// and dropped immediately after.
    pub fn sign(&self, message: &[u8; 32]) -> FuryResult<Signature> {
        let key = SigningKey::from_bytes(self.key_bytes.as_ref())
            .map_err(|_| FuryError::Internal("Failed to reconstruct signing key".into()))?;
        Ok(key.sign_prehash(message)?)
    }
}

/// Test-only constructor: build a `FuryIdentity` directly from a raw 32-byte
/// secp256k1 scalar, bypassing BIP-39/BIP-32 derivation.  Used to run the
/// official NIP-44 test vectors, which supply raw private keys.
#[cfg(test)]
impl FuryIdentity {
    pub(crate) fn from_raw_bytes(bytes: [u8; 32]) -> FuryResult<Self> {
        Ok(Self {
            key_bytes: Box::new(bytes),
        })
    }
}

impl Drop for FuryIdentity {
    fn drop(&mut self) {
        unsafe {
            memsec::munlock(self.key_bytes.as_ref().as_ptr() as *mut _, 32);
        }
        self.key_bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[test]
    fn nip06_vectors() {
        // NIP-06 official test vectors
        // https://github.com/nostr-protocol/nips/blob/master/06.md

        let identity = FuryIdentity::new(SecretString::new(
            "leader monkey parrot ring guide accident before fence cannon height naive bean".into(),
        ))
        .unwrap();
        assert_eq!(
            identity.pubkey_hex(),
            "17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917"
        );

        let identity = FuryIdentity::new(SecretString::new(
        "what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade"
            .into(),
        ))
        .unwrap();
        assert_eq!(
            identity.pubkey_hex(),
            "d41b22899549e1f3d335a31002cfd382174006e166d3e658e3a5eecdb6463573"
        );
    }

    #[test]
    fn sign_is_deterministic() {
        let identity = FuryIdentity::new(SecretString::new(
            "leader monkey parrot ring guide accident before fence cannon height naive bean".into(),
        ))
        .unwrap();
        let msg = [0u8; 32];
        let sig1 = identity.sign(&msg).unwrap();
        let sig2 = identity.sign(&msg).unwrap();
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn sign_output_is_64_bytes() {
        let identity = FuryIdentity::new(SecretString::new(
            "leader monkey parrot ring guide accident before fence cannon height naive bean".into(),
        ))
        .unwrap();
        assert_eq!(identity.sign(&[0u8; 32]).unwrap().to_bytes().len(), 64);
    }

    // M1: npub roundtrip against NIP-06 official test vectors
    // https://github.com/nostr-protocol/nips/blob/master/06.md
    #[test]
    fn npub_nip06_vector() {
        let identity = FuryIdentity::new(SecretString::new(
            "leader monkey parrot ring guide accident before fence cannon height naive bean".into(),
        ))
        .unwrap();
        assert_eq!(
            identity.npub(),
            "npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu"
        );
    }

    #[test]
    fn npub_roundtrip() {
        let identity = FuryIdentity::new(SecretString::new(
            "leader monkey parrot ring guide accident before fence cannon height naive bean".into(),
        ))
        .unwrap();
        let npub = identity.npub();
        assert!(npub.starts_with("npub1"));
        // decode and verify it round-trips back to the same pubkey hex
        let (hrp, data, _) = bech32::decode(&npub).unwrap();
        assert_eq!(hrp, "npub");
        let bytes = <Vec<u8> as bech32::FromBase32>::from_base32(&data).unwrap();
        assert_eq!(hex::encode(bytes), identity.pubkey_hex());
    }

    // M1: wallet key derivation
    #[test]
    fn wallet_key_ethereum_is_deterministic() {
        let mnemonic =
            "leader monkey parrot ring guide accident before fence cannon height naive bean";
        let k1 = derive_wallet_key(SecretString::new(mnemonic.into()), CoinType::Ethereum).unwrap();
        let k2 = derive_wallet_key(SecretString::new(mnemonic.into()), CoinType::Ethereum).unwrap();
        assert_eq!(k1.to_bytes(), k2.to_bytes());
    }

    #[test]
    fn wallet_key_bitcoin_is_deterministic() {
        let mnemonic =
            "leader monkey parrot ring guide accident before fence cannon height naive bean";
        let k1 = derive_wallet_key(SecretString::new(mnemonic.into()), CoinType::Bitcoin).unwrap();
        let k2 = derive_wallet_key(SecretString::new(mnemonic.into()), CoinType::Bitcoin).unwrap();
        assert_eq!(k1.to_bytes(), k2.to_bytes());
    }

    #[test]
    fn wallet_keys_differ_from_each_other() {
        let mnemonic =
            "leader monkey parrot ring guide accident before fence cannon height naive bean";
        let eth =
            derive_wallet_key(SecretString::new(mnemonic.into()), CoinType::Ethereum).unwrap();
        let btc = derive_wallet_key(SecretString::new(mnemonic.into()), CoinType::Bitcoin).unwrap();
        assert_ne!(eth.to_bytes(), btc.to_bytes());
    }
}
