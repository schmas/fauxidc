//! Signing speed per algorithm. Ignored by default: the numbers only mean something in a
//! release build.
//!
//! Run: `cargo test --release --test signing_speed -- --ignored --nocapture`

use std::time::Instant;

use fauxidc::config::types::SigningAlg;
use fauxidc::keys::SigningKey;
use jsonwebtoken::{Header, Validation};
use serde_json::{Value, json};

const RUNS: u32 = 200;

fn time_signing(alg: SigningAlg) {
    let key = SigningKey::generate_for(alg).unwrap();
    let mut header = Header::new(key.alg.jwt());
    header.kid = Some(key.kid.clone());
    let claims = json!({
        "iss": "http://localhost:9000/generic",
        "sub": "service",
        "aud": "https://api.example.test",
        "exp": 4_102_444_800u64,
        "scope": "api",
    });

    let start = Instant::now();
    let mut token = String::new();
    for _ in 0..RUNS {
        token = jsonwebtoken::encode(&header, &claims, &key.encoding).unwrap();
    }
    let per_sign = start.elapsed() / RUNS;

    let mut validation = Validation::new(key.alg.jwt());
    validation.set_audience(&["https://api.example.test"]);
    jsonwebtoken::decode::<Value>(&token, &key.decoding, &validation).unwrap();
    println!("{alg:?}: {per_sign:?} per signature ({RUNS} runs)");
}

#[test]
#[ignore = "timing only; run in release mode"]
fn signing_speed() {
    for alg in [SigningAlg::RS256, SigningAlg::PS256, SigningAlg::ES256] {
        time_signing(alg);
    }
}
