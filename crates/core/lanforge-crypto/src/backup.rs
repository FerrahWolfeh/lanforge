//! Encrypted backup envelope: Argon2id key derivation + XChaCha20-Poly1305.
//!
//! The caller serializes [`BackupEnvelope`] (JSON). Everything except `ciphertext` is the
//! header and is authenticated as AEAD associated data, so tampering with any parameter
//! (KDF cost, salt, nonce, version) makes [`open`] fail.
//!
//! # AAD encoding (version 1)
//!
//! Fixed-order concatenation, independent of any serializer formatting. `u32` is big-endian;
//! `bytes(x)` is `u32(len(x)) || x`:
//!
//! ```text
//! bytes(format) || u32(version)
//!   || bytes(kdf.alg) || u32(m_cost) || u32(t_cost) || u32(p_cost) || bytes(kdf.salt)
//!   || bytes(cipher.alg) || bytes(cipher.nonce)
//! ```

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const FORMAT: &str = "lanforge-backup";
const VERSION: u32 = 1;
const KDF_ALG: &str = "argon2id";
const CIPHER_ALG: &str = "xchacha20poly1305";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

/// Default Argon2id cost for new backups: 64 MiB, 3 passes, 1 lane.
const DEFAULT_M_COST: u32 = 64 * 1024;
const DEFAULT_T_COST: u32 = 3;
const DEFAULT_P_COST: u32 = 1;

/// Upper bounds accepted from an untrusted file (`m_cost` in KiB).
const MAX_M_COST: u32 = 1024 * 1024;
const MAX_T_COST: u32 = 16;
const MAX_P_COST: u32 = 8;

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("not a lanforge backup or unsupported version")]
    UnsupportedFormat,
    #[error("unsupported algorithm in backup header")]
    UnsupportedAlgorithm,
    #[error("backup key-derivation parameters are out of range")]
    InvalidParams,
    #[error("backup is malformed")]
    Malformed,
    #[error("wrong password or corrupted backup")]
    Decrypt,
    #[error("backup encryption failed")]
    Encrypt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfHeader {
    pub alg: String,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CipherHeader {
    pub alg: String,
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupEnvelope {
    pub format: String,
    pub version: u32,
    pub kdf: KdfHeader,
    pub cipher: CipherHeader,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
}

mod b64 {
    use super::{Deserialize, Deserializer, Engine, STANDARD, Serializer};
    use serde::de::Error as _;

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        STANDARD.decode(text).map_err(D::Error::custom)
    }
}

impl BackupEnvelope {
    /// Canonical header bytes used as AEAD associated data (see the module docs).
    fn aad(&self) -> Vec<u8> {
        fn put(out: &mut Vec<u8>, bytes: &[u8]) {
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        let mut out = Vec::with_capacity(128);
        put(&mut out, self.format.as_bytes());
        out.extend_from_slice(&self.version.to_be_bytes());
        put(&mut out, self.kdf.alg.as_bytes());
        out.extend_from_slice(&self.kdf.m_cost.to_be_bytes());
        out.extend_from_slice(&self.kdf.t_cost.to_be_bytes());
        out.extend_from_slice(&self.kdf.p_cost.to_be_bytes());
        put(&mut out, &self.kdf.salt);
        put(&mut out, self.cipher.alg.as_bytes());
        put(&mut out, &self.cipher.nonce);
        out
    }
}

fn derive_key(
    password: &str,
    salt: &[u8],
    m: u32,
    t: u32,
    p: u32,
) -> Result<[u8; KEY_LEN], BackupError> {
    let params = Params::new(m, t, p, Some(KEY_LEN)).map_err(|_| BackupError::InvalidParams)?;
    let mut key = [0u8; KEY_LEN];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| BackupError::InvalidParams)?;
    Ok(key)
}

/// Encrypts `plaintext` under `password` with the default KDF cost.
pub fn seal(password: &str, plaintext: &[u8]) -> Result<BackupEnvelope, BackupError> {
    seal_with_params(
        password,
        plaintext,
        DEFAULT_M_COST,
        DEFAULT_T_COST,
        DEFAULT_P_COST,
    )
}

fn seal_with_params(
    password: &str,
    plaintext: &[u8],
    m: u32,
    t: u32,
    p: u32,
) -> Result<BackupEnvelope, BackupError> {
    let mut salt = vec![0u8; SALT_LEN];
    let mut nonce = vec![0u8; NONCE_LEN];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);

    let mut env = BackupEnvelope {
        format: FORMAT.into(),
        version: VERSION,
        kdf: KdfHeader {
            alg: KDF_ALG.into(),
            m_cost: m,
            t_cost: t,
            p_cost: p,
            salt,
        },
        cipher: CipherHeader {
            alg: CIPHER_ALG.into(),
            nonce,
        },
        ciphertext: Vec::new(),
    };

    let mut key = derive_key(password, &env.kdf.salt, m, t, p)?;
    let result = encrypt(&key, &env, plaintext);
    key.fill(0);
    env.ciphertext = result?;
    Ok(env)
}

fn encrypt(key: &[u8], env: &BackupEnvelope, plaintext: &[u8]) -> Result<Vec<u8>, BackupError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| BackupError::Encrypt)?;
    let nonce = XNonce::try_from(env.cipher.nonce.as_slice()).map_err(|_| BackupError::Encrypt)?;
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &env.aad(),
            },
        )
        .map_err(|_| BackupError::Encrypt)
}

/// Decrypts an envelope. A wrong password and any tampering both yield [`BackupError::Decrypt`].
pub fn open(password: &str, env: &BackupEnvelope) -> Result<Vec<u8>, BackupError> {
    if env.format != FORMAT || env.version != VERSION {
        return Err(BackupError::UnsupportedFormat);
    }
    if env.kdf.alg != KDF_ALG || env.cipher.alg != CIPHER_ALG {
        return Err(BackupError::UnsupportedAlgorithm);
    }
    let kdf = &env.kdf;
    if kdf.m_cost > MAX_M_COST || kdf.t_cost > MAX_T_COST || kdf.p_cost > MAX_P_COST {
        return Err(BackupError::InvalidParams);
    }
    let nonce =
        XNonce::try_from(env.cipher.nonce.as_slice()).map_err(|_| BackupError::Malformed)?;
    let mut key = derive_key(password, &kdf.salt, kdf.m_cost, kdf.t_cost, kdf.p_cost)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| BackupError::Decrypt);
    key.fill(0);
    cipher?
        .decrypt(
            &nonce,
            Payload {
                msg: &env.ciphertext,
                aad: &env.aad(),
            },
        )
        .map_err(|_| BackupError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: u32 = 8;
    const T: u32 = 1;

    fn small(pw: &str, data: &[u8]) -> BackupEnvelope {
        seal_with_params(pw, data, M, T, 1).unwrap()
    }

    #[test]
    fn roundtrip() {
        let env = small("pw", b"hello backup");
        assert_eq!(open("pw", &env).unwrap(), b"hello backup");
    }

    #[test]
    fn default_params_roundtrip() {
        let env = seal("pw", b"x").unwrap();
        assert_eq!(
            (env.kdf.m_cost, env.kdf.t_cost, env.kdf.p_cost),
            (65536, 3, 1)
        );
        assert_eq!(open("pw", &env).unwrap(), b"x");
    }

    #[test]
    fn wrong_password_fails() {
        let env = small("pw", b"data");
        assert!(matches!(open("other", &env), Err(BackupError::Decrypt)));
    }

    #[test]
    fn header_tamper_fails() {
        let env = small("pw", b"data");
        let mut e = env.clone();
        e.kdf.t_cost = 2;
        assert!(matches!(open("pw", &e), Err(BackupError::Decrypt)));
        let mut e = env.clone();
        e.cipher.nonce[0] ^= 1;
        assert!(matches!(open("pw", &e), Err(BackupError::Decrypt)));
        let mut e = env;
        e.kdf.salt[0] ^= 1;
        assert!(matches!(open("pw", &e), Err(BackupError::Decrypt)));
    }

    #[test]
    fn ciphertext_tamper_fails() {
        let mut env = small("pw", b"data");
        env.ciphertext[0] ^= 1;
        assert!(matches!(open("pw", &env), Err(BackupError::Decrypt)));
    }

    #[test]
    fn unknown_version_and_algs_rejected() {
        let env = small("pw", b"data");
        let mut e = env.clone();
        e.version = 2;
        assert!(matches!(
            open("pw", &e),
            Err(BackupError::UnsupportedFormat)
        ));
        let mut e = env.clone();
        e.format = "other".into();
        assert!(matches!(
            open("pw", &e),
            Err(BackupError::UnsupportedFormat)
        ));
        let mut e = env.clone();
        e.kdf.alg = "scrypt".into();
        assert!(matches!(
            open("pw", &e),
            Err(BackupError::UnsupportedAlgorithm)
        ));
        let mut e = env;
        e.cipher.alg = "aes".into();
        assert!(matches!(
            open("pw", &e),
            Err(BackupError::UnsupportedAlgorithm)
        ));
    }

    #[test]
    fn absurd_params_rejected_before_kdf() {
        let env = small("pw", b"data");
        let mut e = env.clone();
        e.kdf.m_cost = u32::MAX;
        assert!(matches!(open("pw", &e), Err(BackupError::InvalidParams)));
        let mut e = env.clone();
        e.kdf.t_cost = 17;
        assert!(matches!(open("pw", &e), Err(BackupError::InvalidParams)));
        let mut e = env;
        e.kdf.p_cost = 9;
        assert!(matches!(open("pw", &e), Err(BackupError::InvalidParams)));
    }

    #[test]
    fn bad_nonce_length_is_an_error_not_a_panic() {
        let mut env = small("pw", b"data");
        env.cipher.nonce.truncate(3);
        assert!(matches!(open("pw", &env), Err(BackupError::Malformed)));
    }

    fn vector() -> BackupEnvelope {
        let b = |s: &str| STANDARD.decode(s).unwrap();
        BackupEnvelope {
            format: "lanforge-backup".into(),
            version: 1,
            kdf: KdfHeader {
                alg: "argon2id".into(),
                m_cost: 8,
                t_cost: 1,
                p_cost: 1,
                salt: b("tkoHXn6ie8pkBbhlGzDu9Q=="),
            },
            cipher: CipherHeader {
                alg: "xchacha20poly1305".into(),
                nonce: b("W8jjvic1GiEv9beKVy9KBk69wFgzLtgw"),
            },
            ciphertext: b("vQAoV3Z6jn4sxo906ecT5JaRz9wN5rJ608qRKiCFxGdjoZvo"),
        }
    }

    #[test]
    fn fixed_vector_still_opens() {
        assert_eq!(
            open("correct horse", &vector()).unwrap(),
            b"lanforge test vector"
        );
    }
}
