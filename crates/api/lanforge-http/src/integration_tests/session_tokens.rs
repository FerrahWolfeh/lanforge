//! Session and elevation tokens: HS256 JWTs (RFC 7519, RFC 7515) signed with the manager's
//! secret. Only the exact header lanforge issues is accepted, so `alg: none` and
//! algorithm-confusion tokens fail before the signature check (RFC 8725 §2.1, §3.1); `exp` is
//! required and honoured with 60 s of clock skew (RFC 7519 §4.1.4).

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use lanforge_crypto::hmac::HmacSha256;

use crate::auth::{AuthManager, Claims};

const SECRET: &[u8] = b"lanforge-test-secret";

/// Issued by `jsonwebtoken` 11 (`Header::default()`, `EncodingKey::from_secret(SECRET)`) for
/// `claims(4_102_444_800, false, 7)` and `claims(4_102_444_800, true, 0)`, before lanforge
/// signed its own tokens: the format did not change.
const JSONWEBTOKEN_SESSION: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImV4cCI6NDEwMjQ0NDgwMCwiZWxldiI6ZmFsc2UsInV2Ijo3fQ.TXjhdvuUOdJFtaLRO6TejV0UJt2_oQ_nYH8pXqSMp44";
const JSONWEBTOKEN_ELEVATION: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImV4cCI6NDEwMjQ0NDgwMCwiZWxldiI6dHJ1ZSwidXYiOjB9.J01g4nM6FXImOZVGbHD-XNnZt1Cw5krquPdoeDvSbvg";

fn claims(exp: u64, elev: bool, uv: i64) -> Claims {
    Claims {
        sub: "admin".into(),
        role: "admin".into(),
        exp: usize::try_from(exp).expect("exp fits"),
        elev,
        uv,
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// A token with any header and payload, signed with `SECRET` the way HS256 does.
fn forge(header: &str, payload: &str) -> String {
    let signed = format!("{}.{}", b64(header.as_bytes()), b64(payload.as_bytes()));
    let tag = HmacSha256::new(SECRET).sign(signed.as_bytes());
    format!("{signed}.{}", b64(&tag))
}

fn payload(exp: u64) -> String {
    format!(r#"{{"sub":"admin","role":"admin","exp":{exp},"elev":false,"uv":0}}"#)
}

#[test]
fn tokens_are_byte_identical_to_the_ones_jsonwebtoken_issued() {
    let auth = AuthManager::from_secret(SECRET);
    assert_eq!(
        auth.sign(&claims(4_102_444_800, false, 7)).expect("sign"),
        JSONWEBTOKEN_SESSION
    );
    assert_eq!(
        auth.sign(&claims(4_102_444_800, true, 0)).expect("sign"),
        JSONWEBTOKEN_ELEVATION
    );

    let session = auth.validate_token(JSONWEBTOKEN_SESSION).expect("valid");
    assert_eq!(
        (session.sub.as_str(), session.elev, session.uv),
        ("admin", false, 7)
    );
    assert!(auth.is_elevated(JSONWEBTOKEN_ELEVATION, "admin"));
    assert!(!auth.is_elevated(JSONWEBTOKEN_ELEVATION, "guest"));
    assert!(!auth.is_elevated(JSONWEBTOKEN_SESSION, "admin"));
}

#[test]
fn a_token_signed_with_another_secret_is_refused() {
    let other = AuthManager::from_secret(b"another secret");
    assert!(other.validate_token(JSONWEBTOKEN_SESSION).is_err());
    assert!(
        AuthManager::new()
            .validate_token(JSONWEBTOKEN_SESSION)
            .is_err()
    );
}

#[test]
fn any_change_to_a_signed_token_is_refused() {
    let auth = AuthManager::from_secret(SECRET);
    let (header, rest) = JSONWEBTOKEN_SESSION.split_once('.').expect("header");
    let (body, sig) = rest.split_once('.').expect("signature");

    // Same claims with a role the token never carried, under the original signature.
    let raised = payload(4_102_444_800).replace(r#""role":"admin""#, r#""role":"root""#);
    let swapped_body = format!("{header}.{}.{sig}", b64(raised.as_bytes()));
    let mut flipped_sig = sig.to_string().into_bytes();
    flipped_sig[0] = if flipped_sig[0] == b'A' { b'B' } else { b'A' };
    let flipped_sig = format!(
        "{header}.{body}.{}",
        String::from_utf8(flipped_sig).expect("ascii")
    );

    for bad in [
        swapped_body.as_str(),
        flipped_sig.as_str(),
        &format!("{header}.{body}."),               // no signature
        &format!("{header}.{body}"),                // two parts
        &format!("{header}.{body}.{sig}.{sig}"),    // four parts
        &format!("{header}.{body}.{sig}A"),         // longer signature
        &format!("{header}.{body}.{}", &sig[..20]), // truncated signature
        &format!("{header}.{body}.{sig}="),         // padded signature
        &format!(" {JSONWEBTOKEN_SESSION}"),
        "",
        "..",
        "invalid.token.here",
    ] {
        assert!(auth.validate_token(bad).is_err(), "{bad}");
    }
}

#[test]
fn only_the_hs256_header_lanforge_issues_is_accepted() {
    let auth = AuthManager::from_secret(SECRET);
    let body = payload(now() + 3600);
    // The accepted header, as a sanity check of `forge`.
    assert!(
        auth.validate_token(&forge(r#"{"typ":"JWT","alg":"HS256"}"#, &body))
            .is_ok()
    );

    for header in [
        r#"{"typ":"JWT","alg":"none"}"#,
        r#"{"alg":"none"}"#,
        r#"{"typ":"JWT","alg":"HS512"}"#,
        r#"{"typ":"JWT","alg":"RS256"}"#,
        r#"{"alg":"HS256","typ":"JWT"}"#,
        r#"{"typ":"JWT","alg":"HS256","kid":"x"}"#,
        r#"{"typ":"JWT","alg":"HS256","crit":["exp"]}"#,
    ] {
        assert!(
            auth.validate_token(&forge(header, &body)).is_err(),
            "{header}"
        );
    }

    // `alg: none` with an empty signature, the classic bypass.
    let unsigned = format!(
        "{}.{}.",
        b64(br#"{"typ":"JWT","alg":"none"}"#),
        b64(body.as_bytes())
    );
    assert!(auth.validate_token(&unsigned).is_err());
}

#[test]
fn expiry_is_honoured_with_sixty_seconds_of_skew() {
    let auth = AuthManager::from_secret(SECRET);
    let hs256 = r#"{"typ":"JWT","alg":"HS256"}"#;
    let now = now();
    assert!(
        auth.validate_token(&forge(hs256, &payload(now + 3600)))
            .is_ok()
    );
    assert!(
        auth.validate_token(&forge(hs256, &payload(now - 30)))
            .is_ok(),
        "within skew"
    );
    assert!(
        auth.validate_token(&forge(hs256, &payload(now - 120)))
            .is_err(),
        "expired"
    );
    assert!(auth.validate_token(&forge(hs256, &payload(0))).is_err());
}

#[test]
fn a_signed_payload_without_valid_claims_is_refused() {
    let auth = AuthManager::from_secret(SECRET);
    let hs256 = r#"{"typ":"JWT","alg":"HS256"}"#;
    for body in [
        r#"{"sub":"admin","role":"admin","elev":false,"uv":0}"#, // no exp
        r#"{"sub":"admin","role":"admin","exp":"never"}"#,
        r#"{"sub":"admin","role":"admin","exp":-1}"#,
        "not json",
        "",
    ] {
        assert!(auth.validate_token(&forge(hs256, body)).is_err(), "{body}");
    }
}

#[test]
fn issued_tokens_round_trip() {
    let auth = AuthManager::new();
    let session = auth.generate_token("ana", "viewer", 42).expect("session");
    let claims = auth.validate_token(&session).expect("valid");
    assert_eq!(
        (claims.sub.as_str(), claims.role.as_str(), claims.uv),
        ("ana", "viewer", 42)
    );
    assert!(!claims.elev);
    let exp = u64::try_from(claims.exp).expect("exp");
    assert!(exp > now() && exp <= now() + 86_400);

    let elevation = auth
        .generate_elevation_token("ana", "viewer")
        .expect("elevation");
    assert!(auth.is_elevated(&elevation, "ana"));
}
