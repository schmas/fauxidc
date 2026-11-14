//! RSA signing key: generation, PEM round trip, JWK and RFC 7638 `kid`.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{DecodingKey, EncodingKey};
use rsa::PrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};

const RSA_BITS: usize = 2048;

/// Errors from creating or loading the signing key.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("invalid key PEM: {0}")]
    InvalidPem(String),
    #[error("key generation failed: {0}")]
    Generate(String),
    #[error("signing key not available")]
    Unavailable,
}

/// RS256 signing key with its public JWK and RFC 7638 `kid`.
#[derive(Clone)]
pub struct SigningKey {
    pub kid: String,
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
    pub jwk: serde_json::Value,
    pkcs8_pem: String,
}

impl SigningKey {
    /// Generate a new RSA 2048 key using the OS random number generator.
    pub fn generate() -> Result<SigningKey, KeyError> {
        let key = PrivateKey::new(&mut getrandom::SysRng, RSA_BITS)
            .map_err(|e| KeyError::Generate(e.to_string()))?;
        Self::from_private_key(&key)
    }

    /// Load a key from a PKCS#8 (`PRIVATE KEY`) or PKCS#1 (`RSA PRIVATE KEY`) PEM.
    pub fn from_pem(pem: &str) -> Result<SigningKey, KeyError> {
        let key = PrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| PrivateKey::from_pkcs1_pem(pem))
            .map_err(|e| KeyError::InvalidPem(e.to_string()))?;
        Self::from_private_key(&key)
    }

    /// The key as a PKCS#8 PEM.
    pub fn to_pem(&self) -> &str {
        &self.pkcs8_pem
    }

    fn from_private_key(key: &PrivateKey) -> Result<SigningKey, KeyError> {
        let pkcs8_pem = key
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| KeyError::InvalidPem(e.to_string()))?
            .to_string();
        let n = URL_SAFE_NO_PAD.encode(key.n_bytes());
        let e = URL_SAFE_NO_PAD.encode(key.e_bytes());
        let kid = thumbprint(&n, &e);
        let encoding = EncodingKey::from_rsa_pem(pkcs8_pem.as_bytes())
            .map_err(|e| KeyError::InvalidPem(e.to_string()))?;
        let decoding = DecodingKey::from_rsa_components(&n, &e)
            .map_err(|e| KeyError::InvalidPem(e.to_string()))?;
        let jwk = serde_json::json!({
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n, "e": e,
        });
        Ok(SigningKey {
            kid,
            encoding,
            decoding,
            jwk,
            pkcs8_pem,
        })
    }
}

/// RFC 7638 JWK thumbprint (SHA-256, base64url without padding) of an RSA public key.
pub(crate) fn thumbprint(n_b64: &str, e_b64: &str) -> String {
    let canonical = format!(r#"{{"e":"{e_b64}","kty":"RSA","n":"{n_b64}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7638 section 3.1 example key modulus.
    const RFC7638_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

    #[test]
    fn generated_key_round_trips_through_pem() {
        let k = SigningKey::generate().unwrap();
        let k2 = SigningKey::from_pem(k.to_pem()).unwrap();
        assert_eq!(k.kid, k2.kid);
        assert_eq!(k.jwk["kty"], "RSA");
        assert_eq!(k.jwk["alg"], "RS256");
        assert_eq!(k.jwk["kid"], k.kid.as_str());
    }

    #[test]
    fn kid_is_rfc7638_thumbprint() {
        assert_eq!(
            thumbprint(RFC7638_N, "AQAB"),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    #[test]
    fn signs_and_verifies() {
        let k = SigningKey::generate().unwrap();
        let mut h = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        h.kid = Some(k.kid.clone());
        let t = jsonwebtoken::encode(
            &h,
            &serde_json::json!({"sub":"x","exp":4_000_000_000u64}),
            &k.encoding,
        )
        .unwrap();
        let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        v.validate_aud = false;
        assert!(jsonwebtoken::decode::<serde_json::Value>(&t, &k.decoding, &v).is_ok());
    }

    #[test]
    fn rejects_garbage_pem() {
        assert!(matches!(
            SigningKey::from_pem("nope"),
            Err(KeyError::InvalidPem(_))
        ));
    }

    #[test]
    fn accepts_pkcs1_pem_and_stores_pkcs8() {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        let k = SigningKey::generate().unwrap();
        let rsa_key = PrivateKey::from_pkcs8_pem(k.to_pem()).unwrap();
        let pkcs1 = rsa_key.to_pkcs1_pem(LineEnding::LF).unwrap();
        assert!(pkcs1.contains("BEGIN RSA PRIVATE KEY"));
        let k2 = SigningKey::from_pem(&pkcs1).unwrap();
        assert_eq!(k.kid, k2.kid);
        assert!(k2.to_pem().contains("BEGIN PRIVATE KEY"));
    }
}
