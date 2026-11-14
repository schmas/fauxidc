//! RSA signing key: generation, PEM round trip, JWK and RFC 7638 `kid`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{DecodingKey, EncodingKey};
use rsa::PrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};
use tokio::sync::watch;

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

/// Where the signing key comes from, in priority order.
#[derive(Debug, Clone, Default)]
pub struct KeySource {
    /// PEM text from the environment. Wins over `key_file`.
    pub pem: Option<String>,
    /// PEM file. Read if it exists; else a generated key is saved here.
    pub key_file: Option<PathBuf>,
}

#[derive(Clone)]
enum KeyState {
    Pending,
    Ready(Arc<SigningKey>),
    Failed,
}

/// Cheap, cloneable access to a signing key that may still be generating.
#[derive(Clone)]
pub struct KeyHandle {
    rx: watch::Receiver<KeyState>,
}

/// Publishes the key (or a failure) to every [`KeyHandle`] clone.
pub struct KeyPublisher(watch::Sender<KeyState>);

impl KeyPublisher {
    pub fn publish(self, key: SigningKey) {
        self.0.send_replace(KeyState::Ready(Arc::new(key)));
    }

    pub fn fail(self) {
        self.0.send_replace(KeyState::Failed);
    }
}

impl KeyHandle {
    /// A handle that already holds `key`.
    pub fn ready(key: SigningKey) -> KeyHandle {
        let (_tx, rx) = watch::channel(KeyState::Ready(Arc::new(key)));
        KeyHandle { rx }
    }

    /// A pending handle and the publisher that completes it.
    pub fn channel() -> (KeyHandle, KeyPublisher) {
        let (tx, rx) = watch::channel(KeyState::Pending);
        (KeyHandle { rx }, KeyPublisher(tx))
    }

    /// Wait until the key is ready. Fails if generation failed or the publisher was dropped.
    pub async fn get(&self) -> Result<Arc<SigningKey>, KeyError> {
        let mut rx = self.rx.clone();
        let state = rx
            .wait_for(|s| !matches!(s, KeyState::Pending))
            .await
            .map_err(|_| KeyError::Unavailable)?;
        match &*state {
            KeyState::Ready(key) => Ok(key.clone()),
            _ => Err(KeyError::Unavailable),
        }
    }

    /// The key if it is ready now.
    pub fn try_get(&self) -> Option<Arc<SigningKey>> {
        match &*self.rx.borrow() {
            KeyState::Ready(key) => Some(key.clone()),
            _ => None,
        }
    }

    /// Resolve the key: `pem`, else an existing `key_file`, else generate in the background
    /// and save to `key_file`. Must run inside a tokio runtime.
    pub fn start(source: KeySource) -> Result<KeyHandle, KeyError> {
        if let Some(pem) = &source.pem {
            return SigningKey::from_pem(pem).map(KeyHandle::ready);
        }
        if let Some(file) = source.key_file.as_deref().filter(|f| f.exists()) {
            let pem = std::fs::read_to_string(file)
                .map_err(|e| KeyError::InvalidPem(format!("{}: {e}", file.display())))?;
            return SigningKey::from_pem(&pem).map(KeyHandle::ready);
        }
        let (handle, publisher) = KeyHandle::channel();
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        let key_file = source.key_file;
        tokio::task::spawn_blocking(move || {
            tracing::dispatcher::with_default(&dispatch, || match SigningKey::generate() {
                Ok(key) => {
                    let pem = key.to_pem().to_owned();
                    publisher.publish(key);
                    if let Some(path) = key_file
                        && let Err(err) = write_key_file(&path, &pem)
                    {
                        tracing::warn!(
                            "cannot write key_file {}: {err}; using the generated key",
                            path.display()
                        );
                    }
                }
                Err(err) => {
                    tracing::error!("cannot generate signing key: {err}");
                    publisher.fail();
                }
            });
        });
        Ok(handle)
    }
}

fn write_key_file(path: &Path, pem: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)?.write_all(pem.as_bytes())
}

/// RFC 7638 JWK thumbprint (SHA-256, base64url without padding) of an RSA public key.
pub(crate) fn thumbprint(n_b64: &str, e_b64: &str) -> String {
    let canonical = format!(r#"{{"e":"{e_b64}","kty":"RSA","n":"{n_b64}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_util::{tmp_path, wait_for_file};
    use std::sync::{LazyLock, Mutex};
    use std::time::Duration;

    static TEST_KEY: LazyLock<SigningKey> = LazyLock::new(|| SigningKey::generate().unwrap());

    fn test_key() -> SigningKey {
        TEST_KEY.clone()
    }

    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn get_waits_for_publish() {
        let (h, p) = KeyHandle::channel();
        assert!(h.try_get().is_none());
        let h2 = h.clone();
        let waiter = tokio::spawn(async move { h2.get().await.map(|k| k.kid.clone()) });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished());
        let key = test_key();
        let kid = key.kid.clone();
        p.publish(key);
        assert_eq!(waiter.await.unwrap().unwrap(), kid);
    }

    #[tokio::test]
    async fn failed_publisher_gives_unavailable() {
        let (h, p) = KeyHandle::channel();
        p.fail();
        assert!(matches!(h.get().await, Err(KeyError::Unavailable)));
    }

    #[tokio::test]
    async fn dropped_publisher_gives_unavailable() {
        let (h, p) = KeyHandle::channel();
        drop(p);
        assert!(matches!(h.get().await, Err(KeyError::Unavailable)));
    }

    #[tokio::test]
    async fn ready_handle_returns_key() {
        let key = test_key();
        let h = KeyHandle::ready(key.clone());
        assert_eq!(h.get().await.unwrap().kid, key.kid);
    }

    #[tokio::test]
    async fn pem_wins_over_file() {
        let file = tmp_path("key.pem");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, SigningKey::generate().unwrap().to_pem()).unwrap();
        let env_key = test_key();
        let h = KeyHandle::start(KeySource {
            pem: Some(env_key.to_pem().into()),
            key_file: Some(file),
        })
        .unwrap();
        assert_eq!(h.try_get().unwrap().kid, env_key.kid);
    }

    #[tokio::test]
    async fn invalid_pem_fails_start() {
        assert!(
            KeyHandle::start(KeySource {
                pem: Some("bad".into()),
                key_file: None
            })
            .is_err()
        );
    }

    #[tokio::test]
    async fn invalid_key_file_fails_start() {
        let file = tmp_path("key.pem");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "bad").unwrap();
        assert!(
            KeyHandle::start(KeySource {
                pem: None,
                key_file: Some(file)
            })
            .is_err()
        );
    }

    #[tokio::test]
    async fn generated_key_is_saved_and_reused() {
        let file = tmp_path("sub/dir/key.pem");
        let h = KeyHandle::start(KeySource {
            pem: None,
            key_file: Some(file.clone()),
        })
        .unwrap();
        let kid = h.get().await.unwrap().kid.clone();
        wait_for_file(&file).await; // the write happens after publish
        // The file may exist before its content is complete; retry the load briefly.
        let mut reused = None;
        for _ in 0..200 {
            if let Ok(h2) = KeyHandle::start(KeySource {
                pem: None,
                key_file: Some(file.clone()),
            }) && let Some(k) = h2.try_get()
            {
                reused = Some(k.kid.clone());
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(reused.as_deref(), Some(kid.as_str()));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn saved_key_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let file = tmp_path("key.pem");
        let h = KeyHandle::start(KeySource {
            pem: None,
            key_file: Some(file.clone()),
        })
        .unwrap();
        h.get().await.unwrap();
        wait_for_file(&file).await;
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[tokio::test]
    async fn unwritable_key_file_still_gives_a_key_and_warns() {
        let logs = Arc::new(Mutex::new(Vec::<u8>::new()));
        let w = logs.clone();
        let sub = tracing_subscriber::fmt()
            .with_writer(move || CaptureWriter(w.clone()))
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(sub);
        let h = KeyHandle::start(KeySource {
            pem: None,
            key_file: Some("/proc/fauxidc/none/key.pem".into()),
        })
        .unwrap();
        assert!(h.get().await.is_ok());
        let mut text = String::new();
        for _ in 0..200 {
            text = String::from_utf8_lossy(&logs.lock().unwrap()).into_owned();
            if text.contains("cannot write key_file") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            text.contains("WARN") && text.contains("cannot write key_file"),
            "{text}"
        );
    }

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
