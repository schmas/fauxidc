//! The `prompt` and `max_age` authorization parameters (OIDC Core 3.1.2.1).

/// What `prompt` and `max_age` ask for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PromptRequest {
    /// `prompt=none`: use the Session only, never show the page.
    pub none: bool,
    /// `login`, `select_account` or `max_age=0`: show the page, skip Auto-select, `auto_login`
    /// and the Session.
    pub force_login: bool,
    pub max_age: Option<u64>,
}

/// Why `prompt` or `max_age` is invalid.
#[derive(Debug, PartialEq, Eq)]
pub enum PromptError {
    /// `none` with any other value. An error in both modes.
    NoneWithOthers,
    /// `max_age` is not a non-negative integer. The value is kept for the message.
    BadMaxAge(String),
}

impl PromptError {
    /// The rule text for the `invalid_request` redirect.
    pub fn rule(&self) -> String {
        match self {
            Self::NoneWithOthers => "prompt=none must not be combined with other values".to_owned(),
            Self::BadMaxAge(value) => format!("max_age must be a non-negative integer: {value}"),
        }
    }
}

/// Parses `prompt` (space-separated) and `max_age`. Empty values count as absent.
/// `consent` and unknown `prompt` values are ignored (logged by the caller if needed).
pub fn parse(prompt: Option<&str>, max_age: Option<&str>) -> Result<PromptRequest, PromptError> {
    let values: Vec<&str> = prompt.unwrap_or_default().split_whitespace().collect();
    let none = values.contains(&"none");
    if none && values.len() > 1 {
        return Err(PromptError::NoneWithOthers);
    }
    let max_age = match max_age.filter(|v| !v.is_empty()) {
        None => None,
        Some(v) => Some(
            v.parse::<u64>()
                .map_err(|_| PromptError::BadMaxAge(v.to_owned()))?,
        ),
    };
    let force_login = values
        .iter()
        .any(|v| matches!(*v, "login" | "select_account"))
        || max_age == Some(0);
    Ok(PromptRequest {
        none,
        force_login,
        max_age,
    })
}

/// The `prompt` values that [`parse`] ignores.
pub fn ignored_values(prompt: Option<&str>) -> Vec<&str> {
    prompt
        .unwrap_or_default()
        .split_whitespace()
        .filter(|v| !matches!(*v, "none" | "login" | "select_account"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_prompt_and_max_age() {
        assert_eq!(
            parse(Some("none"), None),
            Ok(PromptRequest {
                none: true,
                ..Default::default()
            })
        );
        assert!(parse(Some("login consent"), None).unwrap().force_login);
        assert!(parse(Some("select_account"), None).unwrap().force_login);
        assert_eq!(
            parse(Some("consent foo"), None),
            Ok(PromptRequest::default())
        );
        assert_eq!(
            parse(None, Some("0")).unwrap(),
            PromptRequest {
                force_login: true,
                max_age: Some(0),
                ..Default::default()
            }
        );
        assert_eq!(parse(None, Some("300")).unwrap().max_age, Some(300));
        assert_eq!(
            parse(Some("none login"), None),
            Err(PromptError::NoneWithOthers)
        );
        assert!(matches!(
            parse(None, Some("-1")),
            Err(PromptError::BadMaxAge(_))
        ));
        assert!(matches!(
            parse(None, Some("abc")),
            Err(PromptError::BadMaxAge(_))
        ));
        assert_eq!(parse(Some(""), Some("")), Ok(PromptRequest::default()));
    }
}
