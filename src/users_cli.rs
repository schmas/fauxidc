//! `fauxidc users ...`: the Users commands. They edit the config file and need no running
//! server. The logic is in [`crate::users`], shared with the Test API.

use std::io::{Read, Write};

use crate::cli::{UserFields, UsersCommand};
use crate::config::edit::{Edit, EditError};
use crate::config::{Claims, LoadInputs, UserConfig, UserIssuerConfig, load};
use crate::users::{self, UserView};

/// A failed command: the message for stderr and the exit code.
#[derive(Debug)]
pub struct Failure {
    pub code: u8,
    pub message: String,
}

impl From<EditError> for Failure {
    fn from(e: EditError) -> Self {
        Failure {
            code: if e.is_config_error() { 2 } else { 1 },
            message: e.to_string(),
        }
    }
}

fn usage(message: impl Into<String>) -> Failure {
    Failure {
        code: 2,
        message: message.into(),
    }
}

fn io(e: &std::io::Error) -> Failure {
    Failure {
        code: 1,
        message: e.to_string(),
    }
}

/// Runs a Users command. Output goes to `out`; `stdin` is read for `--from -`.
pub fn run(
    command: &UsersCommand,
    inputs: &LoadInputs,
    stdin: &mut dyn Read,
    out: &mut dyn Write,
) -> Result<(), Failure> {
    match command {
        UsersCommand::List { json } => {
            let loaded = load(inputs).map_err(|e| usage(e.to_string()))?;
            let all = users::list(&loaded.config);
            if *json {
                print_json(out, &all)
            } else {
                print_table(out, &all)
            }
        }
        UsersCommand::Get { user_id, json } => {
            let loaded = load(inputs).map_err(|e| usage(e.to_string()))?;
            let Some(user) = loaded.config.user.get(user_id) else {
                return Err(Failure {
                    code: 1,
                    message: format!("unknown user: {user_id}"),
                });
            };
            if *json {
                print_json(out, &users::get(&loaded.config, user_id))
            } else {
                let text = users::to_toml(user_id, user)?;
                out.write_all(text.as_bytes()).map_err(|e| io(&e))
            }
        }
        UsersCommand::Create { user_id, fields } => {
            let user = build_user(fields, stdin)?;
            let edit = users::create(inputs, user_id, &user)?;
            write(out, &edit, "created", user_id)
        }
        UsersCommand::Update {
            user_id,
            fields,
            merge,
        } => {
            if is_empty(fields) {
                return Err(usage(
                    "nothing to change: give --label, --claims, --issuer-claims or --from",
                ));
            }
            let edit = if *merge {
                users::merge(inputs, user_id, &build_patch(fields, stdin)?)?
            } else {
                users::replace(inputs, user_id, &build_user(fields, stdin)?)?
            };
            write(out, &edit, "updated", user_id)
        }
        UsersCommand::Delete { user_id } => {
            let edit = users::remove(inputs, user_id)?;
            write(out, &edit, "deleted", user_id)
        }
    }
}

fn write(out: &mut dyn Write, edit: &Edit, done: &str, id: &str) -> Result<(), Failure> {
    edit.write().map_err(|e| Failure {
        code: 1,
        message: format!("cannot write {}: {e}", edit.path.display()),
    })?;
    writeln!(out, "{done} user {id} in {}", edit.path.display()).map_err(|e| io(&e))
}

fn print_json(out: &mut dyn Write, value: &impl serde::Serialize) -> Result<(), Failure> {
    let text = serde_json::to_string_pretty(value).map_err(|e| usage(e.to_string()))?;
    writeln!(out, "{text}").map_err(|e| io(&e))
}

fn print_table(out: &mut dyn Write, all: &[UserView]) -> Result<(), Failure> {
    let rows: Vec<[String; 3]> = all
        .iter()
        .map(|u| {
            let claims: Vec<&str> = u.claims.keys().map(String::as_str).collect();
            [u.id.clone(), u.label.clone(), claims.join(",")]
        })
        .collect();
    let width = |i: usize, title: &str| {
        rows.iter()
            .map(|r| r[i].chars().count())
            .chain([title.len()])
            .max()
            .unwrap_or(0)
    };
    let (w0, w1) = (width(0, "ID"), width(1, "LABEL"));
    let mut text = format!("{:w0$}  {:w1$}  CLAIMS\n", "ID", "LABEL");
    for [id, label, claims] in &rows {
        text.push_str(format!("{id:w0$}  {label:w1$}  {claims}").trim_end());
        text.push('\n');
    }
    out.write_all(text.as_bytes()).map_err(|e| io(&e))
}

fn is_empty(fields: &UserFields) -> bool {
    fields.label.is_none()
        && fields.claims.is_none()
        && fields.issuer_claims.is_empty()
        && fields.from.is_none()
}

fn read_from(fields: &UserFields, stdin: &mut dyn Read) -> Result<Option<String>, Failure> {
    let Some(path) = &fields.from else {
        return Ok(None);
    };
    let mut text = String::new();
    if path.as_os_str() == "-" {
        stdin.read_to_string(&mut text).map_err(|e| io(&e))?;
    } else {
        text = std::fs::read_to_string(path).map_err(|e| Failure {
            code: 1,
            message: format!("cannot read {}: {e}", path.display()),
        })?;
    }
    Ok(Some(text))
}

fn claims_arg(name: &str, text: &str) -> Result<Claims, Failure> {
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(serde_json::Value::Object(map)) => Ok(map),
        Ok(_) => Err(usage(format!("{name} must be a JSON object"))),
        Err(e) => Err(usage(format!("{name}: invalid JSON: {e}"))),
    }
}

/// `<issuer_id>=<json>` pairs of `--issuer-claims`.
fn issuer_claims(fields: &UserFields) -> Result<Vec<(String, Claims)>, Failure> {
    fields
        .issuer_claims
        .iter()
        .map(|pair| {
            let Some((issuer_id, json)) = pair.split_once('=') else {
                return Err(usage(format!(
                    "--issuer-claims {pair:?}: expected <issuer_id>=<json>"
                )));
            };
            Ok((
                issuer_id.to_owned(),
                claims_arg(&format!("--issuer-claims {issuer_id}"), json)?,
            ))
        })
        .collect()
}

/// The User of `--from` with the other flags applied.
fn build_user(fields: &UserFields, stdin: &mut dyn Read) -> Result<UserConfig, Failure> {
    let mut user = match read_from(fields, stdin)? {
        Some(text) => users::parse_user(&text)?,
        None => UserConfig::default(),
    };
    if let Some(label) = &fields.label {
        user.label.clone_from(label);
    }
    if let Some(claims) = &fields.claims {
        user.claims = claims_arg("--claims", claims)?;
    }
    for (issuer_id, claims) in issuer_claims(fields)? {
        user.issuer.insert(issuer_id, UserIssuerConfig { claims });
    }
    Ok(user)
}

/// A JSON Merge Patch from `--from` with the other flags merged in.
fn build_patch(fields: &UserFields, stdin: &mut dyn Read) -> Result<serde_json::Value, Failure> {
    use serde_json::{Map, Value};
    let mut patch = match read_from(fields, stdin)? {
        Some(text) => users::parse_patch(&text)?,
        None => Value::Object(Map::new()),
    };
    let Value::Object(map) = &mut patch else {
        return Err(usage("--from must hold an object"));
    };
    if let Some(label) = &fields.label {
        map.insert("label".to_owned(), Value::String(label.clone()));
    }
    if let Some(claims) = &fields.claims {
        map.insert(
            "claims".to_owned(),
            Value::Object(claims_arg("--claims", claims)?),
        );
    }
    for (issuer_id, claims) in issuer_claims(fields)? {
        let issuers = map
            .entry("issuer")
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(issuers) = issuers {
            issuers.insert(
                issuer_id,
                serde_json::json!({ "claims": Value::Object(claims) }),
            );
        }
    }
    Ok(patch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_util::*;

    const BASE: &str = "[issuer.a]\nissuer_url = \"http://localhost:9000/a\"\n\n\
                        [user.alice]\nlabel = \"Alice\"\nclaims = { email = \"alice@example.com\" }\n";

    fn file_inputs() -> (LoadInputs, std::path::PathBuf) {
        let file = write_tmp(BASE);
        let mut i = inputs(&[]);
        i.config_files = vec![file.clone()];
        (i, file)
    }

    fn exec(command: &UsersCommand, i: &LoadInputs, stdin: &str) -> Result<String, Failure> {
        let mut out = Vec::new();
        run(command, i, &mut stdin.as_bytes(), &mut out)?;
        Ok(String::from_utf8(out).unwrap())
    }

    fn fields(label: Option<&str>, claims: Option<&str>) -> UserFields {
        UserFields {
            label: label.map(str::to_owned),
            claims: claims.map(str::to_owned),
            ..UserFields::default()
        }
    }

    #[test]
    fn list_prints_a_table_or_json() {
        let (i, _) = file_inputs();
        let text = exec(&UsersCommand::List { json: false }, &i, "").unwrap();
        assert_eq!(text, "ID     LABEL  CLAIMS\nalice  Alice  email\n");
        let text = exec(&UsersCommand::List { json: true }, &i, "").unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v[0]["id"], "alice");
    }

    #[test]
    fn get_prints_toml_or_json() {
        let (i, _) = file_inputs();
        let get = |json| UsersCommand::Get {
            user_id: "alice".into(),
            json,
        };
        assert_eq!(
            exec(&get(false), &i, "").unwrap(),
            "[user.alice]\nlabel = \"Alice\"\nclaims = { email = \"alice@example.com\" }\n"
        );
        assert!(
            exec(&get(true), &i, "")
                .unwrap()
                .contains("\"id\": \"alice\"")
        );
        let missing = UsersCommand::Get {
            user_id: "zed".into(),
            json: false,
        };
        assert_eq!(exec(&missing, &i, "").unwrap_err().code, 1);
    }

    #[test]
    fn create_from_flags_and_stdin() {
        let (i, file) = file_inputs();
        let create = UsersCommand::Create {
            user_id: "bob".into(),
            fields: UserFields {
                issuer_claims: vec!["a={\"sub\": \"b-1\"}".into()],
                ..fields(Some("Bob"), Some("{\"email\": \"bob@example.com\"}"))
            },
        };
        let text = exec(&create, &i, "").unwrap();
        assert_eq!(text, format!("created user bob in {}\n", file.display()));
        let loaded = load(&i).unwrap();
        assert_eq!(loaded.config.user["bob"].issuer["a"].claims["sub"], "b-1");

        let from_stdin = UsersCommand::Create {
            user_id: "carol".into(),
            fields: UserFields {
                from: Some("-".into()),
                ..fields(Some("Carol"), None)
            },
        };
        exec(
            &from_stdin,
            &i,
            "label = \"x\"\nclaims = { email = \"c@example.com\" }\n",
        )
        .unwrap();
        let carol = &load(&i).unwrap().config.user["carol"];
        assert_eq!(carol.label, "Carol", "a flag wins over --from");
        assert_eq!(carol.claims["email"], "c@example.com");

        assert_eq!(exec(&create, &i, "").unwrap_err().code, 1, "exists");
    }

    #[test]
    fn update_replaces_or_merges() {
        let (i, _) = file_inputs();
        let update = |merge, f| UsersCommand::Update {
            user_id: "alice".into(),
            fields: f,
            merge,
        };
        exec(
            &update(true, fields(None, Some("{\"name\": \"A\"}"))),
            &i,
            "",
        )
        .unwrap();
        let alice = &load(&i).unwrap().config.user["alice"];
        assert_eq!(alice.label, "Alice");
        assert_eq!(alice.claims.len(), 2);

        exec(&update(false, fields(Some("A2"), None)), &i, "").unwrap();
        let alice = &load(&i).unwrap().config.user["alice"];
        assert_eq!(alice.label, "A2");
        assert!(alice.claims.is_empty());

        let e = exec(&update(false, UserFields::default()), &i, "").unwrap_err();
        assert_eq!(e.code, 2);
    }

    #[test]
    fn errors_have_exit_codes() {
        let (i, _) = file_inputs();
        let bad_json = UsersCommand::Create {
            user_id: "bob".into(),
            fields: fields(None, Some("[1]")),
        };
        assert_eq!(exec(&bad_json, &i, "").unwrap_err().code, 2);
        let missing = UsersCommand::Delete {
            user_id: "zed".into(),
        };
        assert_eq!(exec(&missing, &i, "").unwrap_err().code, 1);
        let no_file = UsersCommand::Delete {
            user_id: "alice".into(),
        };
        let e = exec(&no_file, &inputs(&[]), "").unwrap_err();
        assert_eq!(e.code, 1, "{}", e.message);
        let delete = UsersCommand::Delete {
            user_id: "alice".into(),
        };
        exec(&delete, &i, "").unwrap();
        assert!(load(&i).unwrap().config.user.is_empty());
    }
}
