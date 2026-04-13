use thiserror::Error;

#[derive(Debug, Error)]
pub enum FuryError {
    /// BIP-39 mnemonic parse/validate errors
    #[error("Mnemonic error: {0}")]
    Identity(#[from] bip39::Error),

    /// BIP-32 path parse or key derivation errors
    #[error("Key derivation error: {0}")]
    Derivation(#[from] bip32::Error),

    /// Errors from the secp256k1 curve (k256)
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] k256::elliptic_curve::Error),

    /// Errors specifically during the signing process
    #[error("Signing failed: {0}")]
    Signature(#[from] k256::ecdsa::Error),

    /// Persistence / I/O errors (for the SEED module)
    #[error("Storage I/O error: {0}")]
    Storage(#[from] std::io::Error),

    /// Networking / Signaling errors (Nostr / Tor)
    #[error("Network error: {0}")]
    Network(String),

    /// Hardware Security Module / Secure Enclave errors
    #[error("HSM/Secure Enclave access denied")]
    HardwareLock,

    /// Catch-all for logic violations
    #[error("Internal logic violation: {0}")]
    Internal(String),

    /// Metadata/Privacy violations (e.g., trying to send un-blinded)
    #[error("Privacy leak prevented: {0}")]
    PrivacyGate(String),
}

/// A specialized Result type for the FURY stack
pub type FuryResult<T> = std::result::Result<T, FuryError>;
