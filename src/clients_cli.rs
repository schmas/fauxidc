//! `fauxidc clients ...`: the Clients commands. They edit the config file and need no running
//! server, so they show no Lenient-registered Clients. The logic is in [`crate::clients_admin`],
//! shared with the Test API.

use std::io::{Read, Write};

use crate::cli::ClientsCommand;
use crate::clients_admin::{self, ClientView, LenientClients};
use crate::config::{LoadInputs, load};
use crate::users_cli::{Failure, io, print_json, read_file, usage, write_edit};

/// Runs a Clients command. Output goes to `out`; `stdin` is read for `--from -`.
pub fn run(
    command: &ClientsCommand,
    inputs: &LoadInputs,
    stdin: &mut dyn Read,
    out: &mut dyn Write,
) -> Result<(), Failure> {
    let none = LenientClients::new();
    match command {
        ClientsCommand::List { json } => {
            let loaded = load(inputs).map_err(|e| usage(e.to_string()))?;
            let all = clients_admin::list(&loaded.config, &none);
            if *json {
                print_json(out, &all)
            } else {
                print_table(out, &all)
            }
        }
        ClientsCommand::Get { client_key, json } => {
            let loaded = load(inputs).map_err(|e| usage(e.to_string()))?;
            let Some(view) = clients_admin::get(&loaded.config, &none, client_key) else {
                return Err(Failure {
                    code: 1,
                    message: format!("unknown client: {client_key}"),
                });
            };
            if *json {
                print_json(out, &view)
            } else {
                let text = clients_admin::to_toml(client_key, &view.client)?;
                out.write_all(text.as_bytes()).map_err(|e| io(&e))
            }
        }
        ClientsCommand::Create { client_key, from } => {
            let client = clients_admin::parse_client(&read_file(from, stdin)?)?;
            let edit = clients_admin::create(inputs, client_key, &client)?;
            write_edit(out, &edit, "created client", client_key)
        }
        ClientsCommand::Update {
            client_key,
            from,
            merge,
        } => {
            let text = read_file(from, stdin)?;
            let edit = if *merge {
                clients_admin::merge(inputs, client_key, &clients_admin::parse_patch(&text)?)?
            } else {
                clients_admin::replace(inputs, client_key, &clients_admin::parse_client(&text)?)?
            };
            write_edit(out, &edit, "updated client", client_key)
        }
        ClientsCommand::Delete { client_key } => {
            let edit = clients_admin::remove(inputs, client_key)?;
            write_edit(out, &edit, "deleted client", client_key)
        }
    }
}

fn print_table(out: &mut dyn Write, all: &[ClientView]) -> Result<(), Failure> {
    const TITLES: [&str; 4] = ["KEY", "CLIENT_ID", "ISSUER", "GRANT_TYPES"];
    let rows: Vec<[String; 4]> = all
        .iter()
        .map(|c| {
            [
                c.key.clone(),
                c.client.client_id.clone().unwrap_or_default(),
                c.client.issuer.clone(),
                c.client.grant_types.join(","),
            ]
        })
        .collect();
    let width = |i: usize| {
        rows.iter()
            .map(|r| r[i].chars().count())
            .chain([TITLES[i].len()])
            .max()
            .unwrap_or(0)
    };
    let (w0, w1, w2) = (width(0), width(1), width(2));
    let mut text = String::new();
    for [key, client_id, issuer, grants] in std::iter::once(TITLES.map(str::to_owned)).chain(rows) {
        text.push_str(format!("{key:w0$}  {client_id:w1$}  {issuer:w2$}  {grants}").trim_end());
        text.push('\n');
    }
    out.write_all(text.as_bytes()).map_err(|e| io(&e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_util::*;

    const BASE: &str = "[issuer.a]\nissuer_url = \"http://localhost:9000/a\"\n\n\
                        [client.web]\nclient_id = \"web-app\"\nclient_secret = \"local\"\n";

    fn file_inputs() -> (LoadInputs, std::path::PathBuf) {
        let file = write_tmp(BASE);
        let mut i = inputs(&[]);
        i.config_files = vec![file.clone()];
        (i, file)
    }

    fn exec(command: &ClientsCommand, i: &LoadInputs, stdin: &str) -> Result<String, Failure> {
        let mut out = Vec::new();
        run(command, i, &mut stdin.as_bytes(), &mut out)?;
        Ok(String::from_utf8(out).unwrap())
    }

    fn from_stdin() -> std::path::PathBuf {
        "-".into()
    }

    #[test]
    fn list_prints_a_table_or_json() {
        let (i, _) = file_inputs();
        let text = exec(&ClientsCommand::List { json: false }, &i, "").unwrap();
        assert_eq!(
            text,
            "KEY  CLIENT_ID  ISSUER  GRANT_TYPES\n\
             web  web-app    *       authorization_code,refresh_token\n"
        );
        let text = exec(&ClientsCommand::List { json: true }, &i, "").unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v[0]["key"], "web");
        assert_eq!(v[0]["client_secret"], "***");
        assert_eq!(v[0]["lenient"], false);
    }

    #[test]
    fn get_prints_masked_toml_or_json() {
        let (i, _) = file_inputs();
        let get = |json| ClientsCommand::Get {
            client_key: "web".into(),
            json,
        };
        assert_eq!(
            exec(&get(false), &i, "").unwrap(),
            "[client.web]\nclient_id = \"web-app\"\nclient_secret = \"***\"\n"
        );
        let json = exec(&get(true), &i, "").unwrap();
        assert!(json.contains("\"client_secret\": \"***\""), "{json}");
        assert!(!json.contains("local"), "{json}");
        let missing = ClientsCommand::Get {
            client_key: "zed".into(),
            json: false,
        };
        assert_eq!(exec(&missing, &i, "").unwrap_err().code, 1);
    }

    #[test]
    fn create_update_and_delete() {
        let (i, file) = file_inputs();
        let create = ClientsCommand::Create {
            client_key: "svc".into(),
            from: from_stdin(),
        };
        let text = exec(
            &create,
            &i,
            "client_secret = \"s\"\ngrant_types = [\"client_credentials\"]\n",
        )
        .unwrap();
        assert_eq!(text, format!("created client svc in {}\n", file.display()));
        let svc = &load(&i).unwrap().config.client["svc"];
        assert_eq!(svc.grant_types, ["client_credentials"]);
        assert_eq!(exec(&create, &i, "{}").unwrap_err().code, 1, "exists");

        let update = |merge| ClientsCommand::Update {
            client_key: "svc".into(),
            from: from_stdin(),
            merge,
        };
        exec(&update(true), &i, r#"{"scopes": ["api"]}"#).unwrap();
        let svc = &load(&i).unwrap().config.client["svc"];
        assert_eq!(svc.scopes, ["api"]);
        assert_eq!(
            svc.client_secret.as_deref(),
            Some("s"),
            "merge keeps the secret"
        );

        exec(&update(false), &i, "require_pkce = true\n").unwrap();
        let svc = &load(&i).unwrap().config.client["svc"];
        assert!(svc.require_pkce && svc.client_secret.is_none());

        let delete = ClientsCommand::Delete {
            client_key: "svc".into(),
        };
        exec(&delete, &i, "").unwrap();
        assert!(!load(&i).unwrap().config.client.contains_key("svc"));
    }

    #[test]
    fn errors_have_exit_codes() {
        let (i, _) = file_inputs();
        let bad = ClientsCommand::Create {
            client_key: "svc".into(),
            from: from_stdin(),
        };
        assert_eq!(exec(&bad, &i, "{\"nope\": 1}").unwrap_err().code, 2);
        let bad_key = ClientsCommand::Create {
            client_key: "Bad-Key".into(),
            from: from_stdin(),
        };
        assert_eq!(exec(&bad_key, &i, "{}").unwrap_err().code, 2);
        let missing_file = ClientsCommand::Create {
            client_key: "svc".into(),
            from: "/nonexistent/client.toml".into(),
        };
        assert_eq!(exec(&missing_file, &i, "").unwrap_err().code, 1);
        let missing = ClientsCommand::Delete {
            client_key: "zed".into(),
        };
        assert_eq!(exec(&missing, &i, "").unwrap_err().code, 1);
        let no_file = ClientsCommand::Delete {
            client_key: "web".into(),
        };
        let e = exec(&no_file, &inputs(&[]), "").unwrap_err();
        assert_eq!(e.code, 1, "{}", e.message);
    }
}
