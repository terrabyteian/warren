//! Signing in (docs/design.md section 6, docs/protocol.md section 11.1):
//! OAuth 2.0 for native apps (RFC 8252) in the system browser, with PKCE
//! (RFC 7636) and a loopback redirect on `127.0.0.1`. The control plane is
//! the IdP's relying party; the client receives a one-time code, exchanges
//! it with a request signed by the device key for a session bound to that
//! key, and enrolls the device. There is nothing to configure beyond the
//! organization URL.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use warren_core::api::{
    DeviceInfo, EnrollRequest, Entitlements, Platform, SESSION_REQUEST_TYP, Session, SessionRequest,
};
use warren_core::clock;
use warren_core::jose::b64url;
use warren_core::keys::{random_bytes, sha256};

use crate::control::{self, Account, ApiError, Call, OrgTrust};
use crate::device::{DeviceKey, KeyStorage};
use crate::state::{DeviceState, Profile, SessionState, Store, StoredCertificate};

/// How long sign-in waits for the browser by default.
pub const SIGN_IN_TIMEOUT: Duration = Duration::from_secs(300);

/// What sign-in needs.
#[derive(Debug, Clone)]
pub struct SignInOptions {
    /// The organization URL, as the person typed it.
    pub org_url: String,
    /// How to verify the organization URL.
    pub trust: OrgTrust,
    /// Where to keep a new device key; `None` prefers the Secure Enclave.
    pub key_storage: Option<KeyStorage>,
    /// Ask the IdP to authenticate afresh (`prompt=login`), as a policy
    /// that needs a recent sign-in requires.
    pub fresh: bool,
    /// How long to wait for the browser.
    pub timeout: Duration,
}

/// What sign-in established.
#[derive(Debug)]
pub struct SignedIn {
    /// The signed-in account.
    pub account: Account,
    /// Whether an existing device key was kept.
    pub reused_key: bool,
    /// Why the Secure Enclave was not used, when it was wanted.
    pub key_note: Option<String>,
    /// The organization a previous sign-in was for, when this one replaced
    /// it.
    pub replaced: Option<String>,
    /// The device as enrolled.
    pub device: DeviceState,
    /// A certificate, when the device is approved.
    pub certificate: Option<StoredCertificate>,
    /// The entitlements, when the device is approved.
    pub entitlements: Option<Entitlements>,
    /// Why there is no certificate yet.
    pub pending: Option<ApiError>,
}

/// Percent-encodes a query value (RFC 3986 unreserved characters pass).
pub fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Decodes a percent-encoded query value, `+` as space.
pub fn decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Parses a query string; a repeated parameter makes it invalid.
pub fn parse_query(query: &str) -> Option<Vec<(String, String)>> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for part in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        let (k, v) = (decode(k)?, decode(v)?);
        if pairs.iter().any(|(n, _)| *n == k) {
            return None;
        }
        pairs.push((k, v));
    }
    Some(pairs)
}

fn param<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// The authorization URL the browser opens.
pub fn authorize_url(
    endpoint: &str,
    redirect_uri: &str,
    challenge: &str,
    state: &str,
    fresh: bool,
) -> String {
    let mut q = format!(
        "redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={}",
        encode(redirect_uri),
        encode(challenge),
        encode(state)
    );
    if fresh {
        q.push_str("&prompt=login");
    }
    let sep = if endpoint.contains('?') { '&' } else { '?' };
    format!("{endpoint}{sep}{q}")
}

fn escape_html(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".into(),
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '"' => "&quot;".into(),
            '\'' => "&#39;".into(),
            c => c.to_string(),
        })
        .collect()
}

fn page(status: &str, title: &str, text: &str) -> Vec<u8> {
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{t}</title>\
         <meta name=\"viewport\" content=\"width=device-width\">\
         <style>body{{font:16px -apple-system,system-ui,sans-serif;margin:15vh auto;max-width:32em;padding:0 1em;color:#222}}\
         @media (prefers-color-scheme:dark){{body{{background:#1c1c1e;color:#eee}}}}h1{{font-size:1.4em}}</style></head>\
         <body><h1>{t}</h1><p>{x}</p></body></html>",
        t = escape_html(title),
        x = escape_html(text)
    );
    format!(
        "HTTP/1.1 {status}\r\ncontent-type: text/html; charset=utf-8\r\ncache-control: no-store\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// What one loopback request said.
enum Callback {
    Code(String),
    Error(String),
    Ignored,
}

/// Reads one request on the loopback listener and answers it.
async fn serve_one(mut s: TcpStream, state: &str) -> Callback {
    let mut buf = Vec::with_capacity(2048);
    let read = async {
        let mut chunk = [0u8; 2048];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 16 * 1024 {
            match s.read(&mut chunk).await {
                Ok(0) | Err(_) => return false,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        true
    };
    if !matches!(
        tokio::time::timeout(Duration::from_secs(10), read).await,
        Ok(true)
    ) {
        return Callback::Ignored;
    }
    let head = String::from_utf8_lossy(&buf);
    let target = head
        .lines()
        .next()
        .and_then(|l| l.strip_prefix("GET "))
        .and_then(|l| l.split(' ').next())
        .unwrap_or("");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let (reply, outcome) = if path != "/callback" {
        (
            page(
                "404 Not Found",
                "Not found",
                "This is warren's sign-in helper.",
            ),
            Callback::Ignored,
        )
    } else {
        match parse_query(query) {
            Some(q) if param(&q, "state") == Some(state) => {
                if let Some(code) = param(&q, "code").filter(|c| !c.is_empty()) {
                    (
                        page(
                            "200 OK",
                            "Signed in to warren",
                            "You can close this tab and return to warren.",
                        ),
                        Callback::Code(code.to_owned()),
                    )
                } else {
                    let why = param(&q, "error_description")
                        .or_else(|| param(&q, "error"))
                        .unwrap_or("The sign-in did not complete.")
                        .to_owned();
                    (
                        page("200 OK", "Sign-in did not complete", &why),
                        Callback::Error(why),
                    )
                }
            }
            // A response for another sign-in, or a forged one: refuse it
            // and keep waiting for ours.
            _ => (
                page(
                    "400 Bad Request",
                    "This sign-in response is not for warren's current sign-in",
                    "Start sign-in again from warren.",
                ),
                Callback::Ignored,
            ),
        }
    };
    let _ = s.write_all(&reply).await;
    let _ = s.shutdown().await;
    outcome
}

/// Waits for the browser to come back with the code.
async fn wait_for_code(
    listener: TcpListener,
    state: &str,
    timeout: Duration,
) -> Result<String, String> {
    let wait = async {
        loop {
            let Ok((s, _)) = listener.accept().await else {
                continue;
            };
            match serve_one(s, state).await {
                Callback::Code(c) => return Ok(c),
                Callback::Error(e) => return Err(format!("sign-in did not complete: {e}")),
                Callback::Ignored => {}
            }
        }
    };
    tokio::time::timeout(timeout, wait).await.map_err(|_| {
        format!(
            "sign-in timed out after {} seconds without the browser coming back; run warren login again",
            timeout.as_secs()
        )
    })?
}

/// Platform facts reported at enrollment.
pub fn platform() -> Platform {
    #[cfg(target_os = "macos")]
    {
        Platform {
            os: "macos".into(),
            os_version: crate::apple::os_version(),
            model: crate::apple::hardware_model(),
            hostname: crate::apple::hostname(),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Platform {
            os: std::env::consts::OS.into(),
            os_version: String::new(),
            model: String::new(),
            hostname: std::fs::read_to_string("/proc/sys/kernel/hostname")
                .map(|h| h.trim().to_owned())
                .unwrap_or_default(),
        }
    }
}

fn https_only(what: &str, url: &str) -> Result<(), String> {
    if url.starts_with("https://") {
        Ok(())
    } else {
        Err(format!("discovery gave a {what} that is not https: {url}"))
    }
}

/// Signs in to the organization and enrolls this device, keeping its
/// existing key when it already signed in to the same organization.
/// `open_browser` shows the user the sign-in page.
pub async fn sign_in(
    store: &Store,
    opts: SignInOptions,
    open_browser: impl FnOnce(&str),
) -> Result<SignedIn, String> {
    let org = control::org_url(&opts.org_url)?;
    let (discovery, bundle) = control::discover(&org, &opts.trust)
        .await
        .map_err(|e| format!("{org}: {e}"))?;
    https_only("authorize endpoint", &discovery.authorize_endpoint)?;
    https_only("token endpoint", &discovery.token_endpoint)?;
    https_only("API base", &discovery.api_base)?;

    // Another organization's sign-in, or a key from a different trust
    // domain, is replaced; the same organization keeps its device key.
    let previous = store.profile().ok().flatten();
    let mut replaced = None;
    let same = previous
        .as_ref()
        .is_some_and(|p| p.org_url == org && p.trust_domain == discovery.trust_domain);
    if let Some(p) = &previous
        && !same
    {
        store.clear()?;
        replaced = Some(p.org_url.clone());
    }
    let reuse = DeviceKey::exists(store.dir())
        && (same || previous.is_none())
        && opts
            .key_storage
            .is_none_or(|want| DeviceKey::load(store.dir()).is_ok_and(|k| k.storage() == want));
    let (key, key_note) = if reuse {
        (DeviceKey::load(store.dir())?, None)
    } else {
        DeviceKey::delete(store.dir())?;
        DeviceKey::create(store.dir(), opts.key_storage)?
    };
    let key = Arc::new(key);

    let verifier = b64url(&random_bytes::<32>().map_err(|e| e.to_string())?);
    let challenge = b64url(&sha256(verifier.as_bytes()));
    let state = b64url(&random_bytes::<16>().map_err(|e| e.to_string())?);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("cannot listen for the browser on 127.0.0.1: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");
    let url = authorize_url(
        &discovery.authorize_endpoint,
        &redirect_uri,
        &challenge,
        &state,
        opts.fresh,
    );
    open_browser(&url);
    let code = wait_for_code(listener, &state, opts.timeout).await?;

    // The session, bound to the device key by a request it signed.
    let request = SessionRequest {
        code,
        code_verifier: verifier,
        redirect_uri,
        iat: clock::now_secs(),
    };
    let jws = key.jws(
        SESSION_REQUEST_TYP,
        &serde_json::to_vec(&request).map_err(|e| e.to_string())?,
    )?;
    let tls = control::org_tls(&opts.trust, Some(&discovery.trust_domain))?;
    let body = control::call(
        &tls,
        Call {
            method: "POST",
            url: &discovery.token_endpoint,
            token: None,
            body: Some(("application/jose", jws.into_bytes())),
        },
    )
    .await
    .map_err(|e| format!("sign-in was refused: {e}"))?;
    let session: Session = control::decode(&body).map_err(|e| e.to_string())?;

    // Enrollment: the device key, where it lives, and platform facts.
    let csr = key.certificate_request()?;
    let enroll = EnrollRequest {
        csr: warren_core::base64::encode(&csr),
        platform: platform(),
        key_storage: key.storage().wire().into(),
    };
    let body = control::call(
        &tls,
        Call {
            method: "POST",
            url: &format!("{}/devices", discovery.api_base),
            token: Some(&session.token),
            body: control::json_body(&enroll),
        },
    )
    .await
    .map_err(|e| format!("device enrollment was refused: {e}"))?;
    let info: DeviceInfo = control::decode(&body).map_err(|e| e.to_string())?;
    https_only("device API base", &info.api_base)?;
    let device = DeviceState::from(&info);

    store.save_trust(&bundle)?;
    let profile = Profile {
        org_url: org,
        trust_domain: discovery.trust_domain.clone(),
        pin: match &opts.trust {
            OrgTrust::Pinned(p) => Some(p.clone()),
            OrgTrust::System => None,
        },
        signin_api_base: discovery.api_base.clone(),
        api_base: Some(info.api_base.clone()),
        user: session.user.clone(),
        session: SessionState {
            id: session.session_id.clone(),
            token: session.token.clone(),
            expires_at: session.expires_at,
            auth_time: session.auth_time,
            mfa: session.mfa,
        },
        device: Some(device.clone()),
    };
    store.save_profile(&profile)?;
    // A certificate from an earlier session is no longer the right one.
    store.clear_certificate();
    let mut account = Account::new(store.clone(), profile, Arc::new(bundle), key)?;

    let (mut certificate, mut entitlements, mut pending) = (None, None, None);
    match device.status.as_str() {
        "approved" => match account.issue_certificate().await {
            Ok(c) => {
                certificate = Some(c);
                entitlements = account.entitlements().await.ok();
            }
            Err(e) => pending = Some(e),
        },
        "pending" => {
            pending = Some(ApiError {
                status: 403,
                reason: "device_not_approved".into(),
                detail: "This device is waiting for an administrator to approve it.".into(),
            });
        }
        other => {
            pending = Some(ApiError {
                status: 403,
                reason: format!("device_{other}"),
                detail: format!("This device is {other}."),
            });
        }
    }
    Ok(SignedIn {
        account,
        reused_key: reuse,
        key_note,
        replaced,
        device,
        certificate,
        entitlements,
        pending,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_values_round_trip() {
        let v = "http://127.0.0.1:5000/callback?x=1&y=ü";
        assert_eq!(decode(&encode(v)).unwrap(), v);
        assert_eq!(decode("a+b%20c").unwrap(), "a b c");
        assert!(decode("%zz").is_none());
        assert!(decode("%4").is_none());
        let q = parse_query("code=abc&state=x%2By&error_description=Not+today").unwrap();
        assert_eq!(param(&q, "state"), Some("x+y"));
        assert_eq!(param(&q, "error_description"), Some("Not today"));
        assert!(parse_query("state=a&state=b").is_none());
    }

    #[test]
    fn authorize_urls_carry_pkce_and_state() {
        let u = authorize_url(
            "https://w.example.com/v1/auth/authorize",
            "http://127.0.0.1:4000/callback",
            "chal",
            "st",
            true,
        );
        assert_eq!(
            u,
            "https://w.example.com/v1/auth/authorize?redirect_uri=http%3A%2F%2F127.0.0.1%3A4000%2Fcallback&code_challenge=chal&code_challenge_method=S256&state=st&prompt=login"
        );
    }

    async fn get(port: u16, target: &str) -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(format!("GET {target} HTTP/1.1\r\nhost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn the_loopback_listener_takes_only_its_own_state() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let wait = tokio::spawn(wait_for_code(listener, "good", Duration::from_secs(10)));
        assert!(get(port, "/favicon.ico").await.starts_with("HTTP/1.1 404"));
        let forged = get(port, "/callback?code=evil&state=bad").await;
        assert!(forged.starts_with("HTTP/1.1 400"), "{forged}");
        let ok = get(port, "/callback?code=c0de&state=good").await;
        assert!(ok.contains("Signed in to warren"));
        assert_eq!(wait.await.unwrap().unwrap(), "c0de");
    }

    #[tokio::test]
    async fn an_idp_refusal_is_shown_and_returned() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let wait = tokio::spawn(wait_for_code(listener, "s", Duration::from_secs(10)));
        let page = get(
            port,
            "/callback?error=access_denied&error_description=Your+account+is+%3Cdisabled%3E&state=s",
        )
        .await;
        assert!(page.contains("Your account is &lt;disabled&gt;"), "{page}");
        let err = wait.await.unwrap().unwrap_err();
        assert!(err.contains("Your account is <disabled>"), "{err}");
    }

    #[tokio::test]
    async fn sign_in_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let err = wait_for_code(listener, "s", Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(err.contains("timed out"));
    }
}
