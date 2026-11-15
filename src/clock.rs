//! The server clock: the system clock, or the time of `server.fixed_time` (ADR 0007).
//!
//! Token times and every token time check read [`Clock::now`] through
//! [`crate::state::AppState::now`]. [`system_now`] is only for the times that ADR 0007 lists
//! as exceptions.

use jsonwebtoken::errors::{Error, ErrorKind};
use jsonwebtoken::{DecodingKey, TokenData, Validation};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::config::Claims;

/// Where the server reads the current time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Clock {
    /// The system clock.
    #[default]
    System,
    /// A fixed time in seconds since the Unix epoch. It does not advance.
    Fixed(u64),
}

impl Clock {
    /// The clock of a `server.fixed_time` value. Empty gives the system clock.
    pub fn from_fixed_time(value: &str) -> Result<Clock, String> {
        if value.is_empty() {
            Ok(Clock::System)
        } else {
            parse_fixed_time(value).map(Clock::Fixed)
        }
    }

    /// The current time in seconds since the Unix epoch.
    #[must_use]
    pub fn now(self) -> u64 {
        match self {
            Clock::System => system_now(),
            Clock::Fixed(secs) => secs,
        }
    }
}

/// The system clock in seconds since the Unix epoch.
#[must_use]
pub fn system_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Parses an RFC 3339 date-time with an offset, for example `2020-01-21T00:00:00Z`, into whole
/// seconds since the Unix epoch. Fractions of a second are dropped. A time before 1970 is an
/// error.
pub fn parse_fixed_time(value: &str) -> Result<u64, String> {
    let invalid = || {
        format!(
            "server.fixed_time: invalid time \"{value}\": use an RFC 3339 date-time at or \
             after 1970-01-01T00:00:00Z, for example \"2020-01-21T00:00:00Z\""
        )
    };
    let time = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| invalid())?;
    u64::try_from(time.unix_timestamp()).map_err(|_| invalid())
}

/// Decodes `token` like `jsonwebtoken::decode`, but checks `exp` and `nbf` against `now`, not
/// against the system clock. The checks follow `validation`: `validate_exp`, `validate_nbf`,
/// `leeway` and `reject_tokens_expiring_in_less_than` keep their `jsonwebtoken` meaning.
/// The time checks run after the other checks of `validation`.
pub fn decode_at(
    token: &str,
    key: &DecodingKey,
    validation: &Validation,
    now: u64,
) -> Result<TokenData<Claims>, Error> {
    let mut without_time = validation.clone();
    without_time.validate_exp = false;
    without_time.validate_nbf = false;
    let data = jsonwebtoken::decode::<Claims>(token, key, &without_time)?;
    check_times(&data.claims, validation, now)?;
    Ok(data)
}

/// The `exp` and `nbf` checks of `jsonwebtoken` 12, with `now` in place of the system clock.
fn check_times(claims: &Claims, v: &Validation, now: u64) -> Result<(), Error> {
    if !v.validate_exp && !v.validate_nbf {
        return Ok(());
    }
    let read = |name: &str| -> Result<Option<u64>, Error> {
        match claims.get(name) {
            None => Ok(None),
            Some(value) => value
                .as_u64()
                .map(Some)
                .ok_or_else(|| ErrorKind::InvalidClaimFormat(name.to_owned()).into()),
        }
    };
    let exp = read("exp");
    let nbf = read("nbf");
    if v.validate_exp && exp.is_err() {
        return Err(ErrorKind::InvalidClaimFormat("exp".to_owned()).into());
    }
    if v.validate_nbf && nbf.is_err() {
        return Err(ErrorKind::InvalidClaimFormat("nbf".to_owned()).into());
    }
    let exp = exp.ok().flatten();
    let nbf = nbf.ok().flatten();
    if let Some(exp) = exp {
        if exp < v.reject_tokens_expiring_in_less_than {
            return Err(ErrorKind::InvalidToken.into());
        }
        if v.validate_exp
            && exp - v.reject_tokens_expiring_in_less_than < now.saturating_sub(v.leeway)
        {
            return Err(ErrorKind::ExpiredSignature.into());
        }
    }
    if let Some(nbf) = nbf
        && v.validate_nbf
        && nbf > now.saturating_add(v.leeway)
    {
        return Err(ErrorKind::ImmatureSignature.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn parses_rfc_3339() {
        assert_eq!(parse_fixed_time("2020-01-21T00:00:00Z"), Ok(1_579_564_800));
        assert_eq!(
            parse_fixed_time("2020-01-21T01:00:00.75+01:00"),
            Ok(1_579_564_800)
        );
        assert_eq!(parse_fixed_time("1970-01-01T00:00:00Z"), Ok(0));
        for bad in [
            "",
            "2020-01-21",
            "now",
            "1969-12-31T23:59:59Z",
            "2020-01-21 00:00:00",
        ] {
            let e = parse_fixed_time(bad).unwrap_err();
            assert!(
                e.starts_with("server.fixed_time: invalid time"),
                "{bad}: {e}"
            );
        }
    }

    #[test]
    fn empty_value_is_the_system_clock() {
        assert_eq!(Clock::from_fixed_time(""), Ok(Clock::System));
        assert_eq!(
            Clock::from_fixed_time("2020-01-21T00:00:00Z"),
            Ok(Clock::Fixed(1_579_564_800))
        );
        assert_eq!(Clock::Fixed(7).now(), 7);
        assert!(Clock::System.now() > 1_600_000_000);
    }

    fn claims(v: &Value) -> Claims {
        v.as_object().unwrap().clone()
    }

    fn check(c: &Value, exp: bool, nbf: bool, leeway: u64, now: u64) -> Result<(), ErrorKind> {
        let v = Validation {
            validate_exp: exp,
            validate_nbf: nbf,
            leeway,
            ..Validation::default()
        };
        check_times(&claims(c), &v, now).map_err(Error::into_kind)
    }

    #[test]
    fn exp_and_nbf_use_the_given_time() {
        let c = json!({ "exp": 100, "nbf": 50 });
        assert_eq!(check(&c, true, true, 0, 100), Ok(()));
        assert_eq!(
            check(&c, true, true, 0, 101),
            Err(ErrorKind::ExpiredSignature)
        );
        assert_eq!(check(&c, true, true, 5, 105), Ok(()));
        assert_eq!(
            check(&c, true, true, 0, 49),
            Err(ErrorKind::ImmatureSignature)
        );
        assert_eq!(check(&c, true, true, 1, 49), Ok(()));
        assert_eq!(check(&c, false, true, 0, 1000), Ok(()));
        assert_eq!(check(&c, true, false, 0, 0), Ok(()));
    }

    #[test]
    fn malformed_time_claims() {
        let c = json!({ "exp": "soon", "nbf": -1 });
        assert_eq!(
            check(&c, true, false, 0, 0),
            Err(ErrorKind::InvalidClaimFormat("exp".into()))
        );
        assert_eq!(
            check(&c, false, true, 0, 0),
            Err(ErrorKind::InvalidClaimFormat("nbf".into()))
        );
        assert_eq!(check(&c, false, false, 0, 0), Ok(()));
        assert_eq!(
            check(&json!({ "exp": 1.0e3 }), true, false, 0, 0),
            Err(ErrorKind::InvalidClaimFormat("exp".into()))
        );
    }
}
