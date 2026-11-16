//! Sessions: who signed in at `/authorize` of one Issuer, kept in memory until restart.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::error::OAuthError;
use crate::state::Subject;

/// The most Sessions the store keeps. Above it, the oldest `auth_time` is dropped.
pub const MAX_SESSIONS: usize = 10_000;

/// One sign-in at `/authorize`.
#[derive(Debug, Clone)]
pub struct Session {
    pub issuer_id: String,
    pub subject: Subject,
    /// UUID v4; the ID token `sid` claim.
    pub sid: String,
    pub auth_time: u64,
}

/// Sessions by cookie value.
#[derive(Default)]
pub struct SessionStore {
    sessions: Mutex<HashMap<String, Session>>,
}

impl SessionStore {
    /// Stores the Session under a new random cookie value (32 bytes, base64url) and returns it.
    /// Above [`MAX_SESSIONS`], drops the Session with the smallest `auth_time` first.
    pub fn create(&self, s: Session) -> Result<String, OAuthError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|e| OAuthError::ServerError(format!("random source failed: {e}")))?;
        let value = URL_SAFE_NO_PAD.encode(bytes);
        let mut sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
        while sessions.len() >= MAX_SESSIONS {
            let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, s)| s.auth_time)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            sessions.remove(&oldest);
        }
        sessions.insert(value.clone(), s);
        Ok(value)
    }

    /// The Session for this cookie value if it belongs to `issuer_id`.
    pub fn get(&self, issuer_id: &str, value: &str) -> Option<Session> {
        self.sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(value)
            .filter(|s| s.issuer_id == issuer_id)
            .cloned()
    }

    /// Deletes the Session for this cookie value if it belongs to `issuer_id`.
    /// Removes every Session, or only the Sessions of `issuer_id`.
    pub fn clear(&self, issuer_id: Option<&str>) {
        self.sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, s| issuer_id.is_some_and(|id| s.issuer_id != id));
    }

    pub fn remove(&self, issuer_id: &str, value: &str) {
        let mut sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
        if sessions
            .get(value)
            .is_some_and(|s| s.issuer_id == issuer_id)
        {
            sessions.remove(value);
        }
    }

    /// The number of stored Sessions.
    pub fn len(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// `true` if no Session is stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Claims;

    fn session(issuer: &str, auth_time: u64) -> Session {
        Session {
            issuer_id: issuer.to_owned(),
            subject: Subject::Custom {
                sub: "c-1".into(),
                claims: Claims::new(),
            },
            sid: uuid::Uuid::new_v4().to_string(),
            auth_time,
        }
    }

    #[test]
    fn get_checks_the_issuer_id() {
        let store = SessionStore::default();
        let value = store.create(session("auth0", 1)).unwrap();
        assert_eq!(value.len(), 43);
        assert!(store.get("auth0", &value).is_some());
        assert!(store.get("okta", &value).is_none());
        assert!(store.get("auth0", "other").is_none());
    }

    #[test]
    fn remove_deletes_the_session() {
        let store = SessionStore::default();
        let value = store.create(session("auth0", 1)).unwrap();
        store.remove("auth0", &value);
        assert!(store.get("auth0", &value).is_none());
        assert!(store.is_empty());
    }

    #[test]
    fn remove_ignores_another_issuers_session() {
        let store = SessionStore::default();
        let value = store.create(session("auth0", 1)).unwrap();
        store.remove("okta", &value);
        assert!(store.get("auth0", &value).is_some());
        store.remove("auth0", &value);
        assert!(store.get("auth0", &value).is_none());
    }

    #[test]
    fn create_above_the_cap_drops_the_oldest() {
        let store = SessionStore::default();
        let mut values = Vec::new();
        for i in 0..=MAX_SESSIONS {
            values.push(store.create(session("auth0", i as u64)).unwrap());
        }
        assert_eq!(store.len(), MAX_SESSIONS);
        assert!(store.get("auth0", &values[0]).is_none());
        assert!(store.get("auth0", &values[1]).is_some());
        assert!(store.get("auth0", &values[MAX_SESSIONS]).is_some());
    }
}
