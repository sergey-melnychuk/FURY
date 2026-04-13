/// NIP-44 v2 — Versioned encrypted payloads for Nostr direct messages.
///
/// Spec: https://github.com/nostr-protocol/nips/blob/master/44.md
///
/// Encryption pipeline for a single message:
///   conversation_key = HKDF-extract(salt="nip44-v2", ikm=ECDH(priv_a, pub_b))
///   nonce            = random 32 bytes
///   chacha_key  (32) │
///   chacha_nonce(12) ├─ HKDF-expand(prk=conversation_key, info=nonce, len=76)
///   hmac_key    (32) │
///   padded           = len_prefix(2 BE) ∥ plaintext ∥ zero_pad → calc_padded_len(len)
///   ciphertext       = ChaCha20(key, nonce, padded)   [stream cipher, no tag]
///   mac              = HMAC-SHA256(hmac_key, nonce ∥ ciphertext)
///   payload          = 0x02 ∥ nonce ∥ ciphertext ∥ mac   → base64
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

use crate::error::{FuryError, FuryResult};
use crate::identity::FuryIdentity;

type HmacSha256 = Hmac<Sha256>;

/// Derive the NIP-44 conversation key shared between two Nostr identities.
///
/// Both sides compute the same key:
///   `conversation_key(alice, bob_pubkey) == conversation_key(bob, alice_pubkey)`
///
/// Returns a 32-byte PRK used as input to `encrypt` / `decrypt`.
pub fn conversation_key(identity: &FuryIdentity, peer_pubkey_hex: &str) -> FuryResult<[u8; 32]> {
    let shared_x = identity.ecdh_shared_secret(peer_pubkey_hex)?;
    let (prk, _) = Hkdf::<Sha256>::extract(Some(b"nip44-v2"), &shared_x);
    let mut conv_key = [0u8; 32];
    conv_key.copy_from_slice(&prk);
    Ok(conv_key)
}

/// Encrypt `plaintext` with the given NIP-44 conversation key.
///
/// Returns a base64-encoded versioned payload (version byte 0x02).
pub fn encrypt(conv_key: &[u8; 32], plaintext: &str) -> FuryResult<String> {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    encrypt_inner(conv_key, plaintext, &nonce)
}

/// Deterministic encrypt with a caller-supplied nonce.
/// Only available in tests — used to reproduce official NIP-44 test vectors.
#[cfg(test)]
pub(crate) fn encrypt_with_nonce(
    conv_key: &[u8; 32],
    plaintext: &str,
    nonce: &[u8; 32],
) -> FuryResult<String> {
    encrypt_inner(conv_key, plaintext, nonce)
}

fn encrypt_inner(conv_key: &[u8; 32], plaintext: &str, nonce: &[u8; 32]) -> FuryResult<String> {
    let (chacha_key, chacha_nonce, hmac_key) = message_keys(conv_key, nonce)?;

    let mut ciphertext = pad(plaintext.as_bytes())?;
    let mut cipher = ChaCha20::new(&chacha_key.into(), &chacha_nonce.into());
    cipher.apply_keystream(&mut ciphertext);

    let mut mac = <HmacSha256 as Mac>::new_from_slice(&hmac_key)
        .map_err(|_| FuryError::Internal("Invalid HMAC key length".into()))?;
    mac.update(nonce);
    mac.update(&ciphertext);
    let mac_bytes = mac.finalize().into_bytes();

    let mut payload = Vec::with_capacity(1 + 32 + ciphertext.len() + 32);
    payload.push(0x02u8);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&mac_bytes);

    Ok(BASE64.encode(&payload))
}

/// Decrypt a NIP-44 v2 base64 payload.
///
/// Verifies the HMAC before attempting decryption (authenticate-then-decrypt).
pub fn decrypt(conv_key: &[u8; 32], ciphertext_b64: &str) -> FuryResult<String> {
    let payload = BASE64
        .decode(ciphertext_b64)
        .map_err(|_| FuryError::Internal("NIP-44: invalid base64".into()))?;

    // Minimum: 1 (version) + 32 (nonce) + 1 (min ciphertext) + 32 (mac) = 66
    if payload.len() < 66 {
        return Err(FuryError::Internal("NIP-44: payload too short".into()));
    }

    let version = payload[0];
    if version != 2 {
        return Err(FuryError::Internal(format!(
            "NIP-44: unsupported version {version}"
        )));
    }

    let nonce: [u8; 32] = payload[1..33].try_into().unwrap();
    let mac_start = payload.len() - 32;
    let ciphertext = &payload[33..mac_start];
    let mac_received = &payload[mac_start..];

    let (chacha_key, chacha_nonce, hmac_key) = message_keys(conv_key, &nonce)?;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(&hmac_key)
        .map_err(|_| FuryError::Internal("Invalid HMAC key length".into()))?;
    mac.update(&nonce);
    mac.update(ciphertext);
    mac.verify_slice(mac_received)
        .map_err(|_| FuryError::Internal("NIP-44: MAC verification failed".into()))?;

    let mut plaintext_padded = ciphertext.to_vec();
    let mut cipher = ChaCha20::new(&chacha_key.into(), &chacha_nonce.into());
    cipher.apply_keystream(&mut plaintext_padded);

    let plaintext_bytes = unpad(&plaintext_padded)?;
    String::from_utf8(plaintext_bytes)
        .map_err(|_| FuryError::Internal("NIP-44: decrypted payload is not valid UTF-8".into()))
}

fn message_keys(
    conv_key: &[u8; 32],
    nonce: &[u8; 32],
) -> FuryResult<([u8; 32], [u8; 12], [u8; 32])> {
    let hkdf = Hkdf::<Sha256>::from_prk(conv_key)
        .map_err(|_| FuryError::Internal("NIP-44: invalid PRK length".into()))?;
    let mut keys = [0u8; 76];
    hkdf.expand(nonce, &mut keys)
        .map_err(|_| FuryError::Internal("NIP-44: HKDF expand failed".into()))?;

    let chacha_key: [u8; 32] = keys[0..32].try_into().unwrap();
    let chacha_nonce: [u8; 12] = keys[32..44].try_into().unwrap();
    let hmac_key: [u8; 32] = keys[44..76].try_into().unwrap();
    Ok((chacha_key, chacha_nonce, hmac_key))
}

/// NIP-44 padding: 2-byte big-endian length prefix, then plaintext, then zeros
/// to reach `2 + calc_padded_len(len)` total bytes.
fn pad(plaintext: &[u8]) -> FuryResult<Vec<u8>> {
    let len = plaintext.len();
    if len == 0 || len > 65536 - 128 {
        return Err(FuryError::Internal(format!(
            "NIP-44: plaintext length {len} out of range 1..=65408"
        )));
    }
    let padded_len = calc_padded_len(len);
    let mut buf = Vec::with_capacity(2 + padded_len);
    buf.push((len >> 8) as u8);
    buf.push((len & 0xff) as u8);
    buf.extend_from_slice(plaintext);
    buf.resize(2 + padded_len, 0);
    Ok(buf)
}

/// Returns the padded plaintext length (excluding the 2-byte prefix).
/// Matches the reference: https://github.com/paulmillr/nip44
fn calc_padded_len(len: usize) -> usize {
    if len <= 32 {
        return 32;
    }
    let next_power = 1usize << ((len - 1).ilog2() + 1);
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    chunk * ((len - 1) / chunk + 1)
}

fn unpad(padded: &[u8]) -> FuryResult<Vec<u8>> {
    if padded.len() < 2 {
        return Err(FuryError::Internal("NIP-44: padded too short".into()));
    }
    let len = ((padded[0] as usize) << 8) | (padded[1] as usize);
    if 2 + len > padded.len() {
        return Err(FuryError::Internal(
            "NIP-44: encoded length exceeds padded buffer".into(),
        ));
    }
    Ok(padded[2..2 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::FuryIdentity;
    use secrecy::SecretString;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex32(s: &str) -> [u8; 32] {
        hex(s).try_into().unwrap()
    }

    fn alice() -> FuryIdentity {
        FuryIdentity::new(SecretString::new(
            "leader monkey parrot ring guide accident before fence cannon height naive bean".into(),
        ))
        .unwrap()
    }

    fn bob() -> FuryIdentity {
        FuryIdentity::new(SecretString::new(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
        ))
        .unwrap()
    }

    #[test]
    fn conversation_key_is_symmetric() {
        let a = alice();
        let b = bob();
        let key_ab = conversation_key(&a, &b.pubkey_hex()).unwrap();
        let key_ba = conversation_key(&b, &a.pubkey_hex()).unwrap();
        assert_eq!(key_ab, key_ba, "ECDH must be commutative");
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let a = alice();
        let b = bob();
        let conv = conversation_key(&a, &b.pubkey_hex()).unwrap();
        let ciphertext = encrypt(&conv, "hello from FURY").unwrap();
        assert_eq!(decrypt(&conv, &ciphertext).unwrap(), "hello from FURY");
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let a = alice();
        let b = bob();
        let conv = conversation_key(&a, &b.pubkey_hex()).unwrap();
        let ciphertext = encrypt(&conv, "secret").unwrap();
        let mut bad_key = conv;
        bad_key[0] ^= 0xff;
        assert!(decrypt(&bad_key, &ciphertext).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails_decrypt() {
        let a = alice();
        let b = bob();
        let conv = conversation_key(&a, &b.pubkey_hex()).unwrap();
        let mut payload = BASE64.decode(encrypt(&conv, "secret").unwrap()).unwrap();
        payload[33] ^= 0x01;
        assert!(decrypt(&conv, &BASE64.encode(&payload)).is_err());
    }

    #[test]
    fn long_message_roundtrip() {
        let a = alice();
        let b = bob();
        let conv = conversation_key(&a, &b.pubkey_hex()).unwrap();
        let long_msg = "A".repeat(1000);
        assert_eq!(
            decrypt(&conv, &encrypt(&conv, &long_msg).unwrap()).unwrap(),
            long_msg
        );
    }

    #[test]
    fn padding_sizes() {
        // total = 2 (prefix) + calc_padded_len(len)
        assert_eq!(pad(b"x").unwrap().len(), 2 + 32); // len=1  → 34
        assert_eq!(pad(&[0u8; 30]).unwrap().len(), 2 + 32); // len=30 → 34
        assert_eq!(pad(&[0u8; 31]).unwrap().len(), 2 + 32); // len=31 → 34
        assert_eq!(pad(&[0u8; 32]).unwrap().len(), 2 + 32); // len=32 → 34
        assert_eq!(pad(&[0u8; 33]).unwrap().len(), 2 + 64); // len=33 → 66
        assert_eq!(pad(&[0u8; 64]).unwrap().len(), 2 + 64); // len=64 → 66
        assert_eq!(pad(&[0u8; 65]).unwrap().len(), 2 + 96); // len=65 → 98
    }

    // Official NIP-44 v2 test vectors — https://github.com/paulmillr/nip44/blob/main/nip44.vectors.json

    #[test]
    fn nip44_conversation_key_vectors() {
        let cases = [
            (
                "315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268",
                "c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133",
                "3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1",
            ),
            (
                "a1e37752c9fdc1273be53f68c5f74be7c8905728e8de75800b94262f9497c86e",
                "03bb7947065dde12ba991ea045132581d0954f042c84e06d8c00066e23c1a800",
                "4d14f36e81b8452128da64fe6f1eae873baae2f444b02c950b90e43553f2178b",
            ),
            (
                "98a5902fd67518a0c900f0fb62158f278f94a21d6f9d33d30cd3091195500311",
                "aae65c15f98e5e677b5050de82e3aba47a6fe49b3dab7863cf35d9478ba9f7d1",
                "9c00b769d5f54d02bf175b7284a1cbd28b6911b06cda6666b2243561ac96bad7",
            ),
            (
                "86ae5ac8034eb2542ce23ec2f84375655dab7f836836bbd3c54cefe9fdc9c19f",
                "59f90272378089d73f1339710c02e2be6db584e9cdbe86eed3578f0c67c23585",
                "19f934aafd3324e8415299b64df42049afaa051c71c98d0aa10e1081f2e3e2ba",
            ),
            (
                "2528c287fe822421bc0dc4c3615878eb98e8a8c31657616d08b29c00ce209e34",
                "f66ea16104c01a1c532e03f166c5370a22a5505753005a566366097150c6df60",
                "c833bbb292956c43366145326d53b955ffb5da4e4998a2d853611841903f5442",
            ),
        ];
        for (sec1, pub2, expected) in cases {
            let identity = FuryIdentity::from_raw_bytes(hex32(sec1)).unwrap();
            let got = conversation_key(&identity, pub2).unwrap();
            assert_eq!(hex::encode(got), expected, "sec1={sec1}");
        }
    }

    #[test]
    fn nip44_encrypt_vectors() {
        let cases = [
            (
                "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d",
                "0000000000000000000000000000000000000000000000000000000000000001",
                "a",
                "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb",
            ),
            (
                "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d",
                "f00000000000000000000000000000f00000000000000000000000000000000f",
                "🍕🫃",
                "AvAAAAAAAAAAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAAPSKSK6is9ngkX2+cSq85Th16oRTISAOfhStnixqZziKMDvB0QQzgFZdjLTPicCJaV8nDITO+QfaQ61+KbWQIOO2Yj",
            ),
            (
                "3e2b52a63be47d34fe0a80e34e73d436d6963bc8f39827f327057a9986c20a45",
                "b635236c42db20f021bb8d1cdff5ca75dd1a0cc72ea742ad750f33010b24f73b",
                "表ポあA鷗ŒéＢ逍Üßªąñ丂㐀𠀀",
                "ArY1I2xC2yDwIbuNHN/1ynXdGgzHLqdCrXUPMwELJPc7s7JqlCMJBAIIjfkpHReBPXeoMCyuClwgbT419jUWU1PwaNl4FEQYKCDKVJz+97Mp3K+Q2YGa77B6gpxB/lr1QgoqpDf7wDVrDmOqGoiPjWDqy8KzLueKDcm9BVP8xeTJIxs=",
            ),
            (
                "d5a2f879123145a4b291d767428870f5a8d9e5007193321795b40183d4ab8c2b",
                "b20989adc3ddc41cd2c435952c0d59a91315d8c5218d5040573fc3749543acaf",
                "ability🤝的 ȺȾ",
                "ArIJia3D3cQc0sQ1lSwNWakTFdjFIY1QQFc/w3SVQ6yvbG2S0x4Yu86QGwPTy7mP3961I1XqB6SFFTzqDZZavhxoWMj7mEVGMQIsh2RLWI5EYQaQDIePSnXPlzf7CIt+voTD",
            ),
            (
                "3b15c977e20bfe4b8482991274635edd94f366595b1a3d2993515705ca3cedb8",
                "8d4442713eb9d4791175cb040d98d6fc5be8864d6ec2f89cf0895a2b2b72d1b1",
                "pepper👀їжак",
                "Ao1EQnE+udR5EXXLBA2Y1vxb6IZNbsL4nPCJWisrctGxY3AduCS+jTUgAAnfvKafkmpy15+i9YMwCdccisRa8SvzW671T2JO4LFSPX31K4kYUKelSAdSPwe9NwO6LhOsnoJ+",
            ),
        ];
        for (conv_key_hex, nonce_hex, plaintext, expected_payload) in cases {
            let conv_key = hex32(conv_key_hex);
            let nonce = hex32(nonce_hex);
            let got = encrypt_with_nonce(&conv_key, plaintext, &nonce).unwrap();
            assert_eq!(got, expected_payload, "plaintext={plaintext:?}");
            assert_eq!(
                decrypt(&conv_key, &got).unwrap(),
                plaintext,
                "decrypt plaintext={plaintext:?}"
            );
        }
    }
}
