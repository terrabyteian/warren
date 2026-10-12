//! Built-in accounts: password hashing, authenticator codes (TOTP, RFC
//! 6238), recovery codes, the per-source limit on failed sign-ins, the
//! lockout of unknown usernames, and the QR code an authenticator app
//! scans.
//!
//! Every primitive comes from aws-lc-rs, warren's one crypto provider:
//! passwords are hashed with PBKDF2-HMAC-SHA256 and authenticator codes are
//! HMAC-SHA1 as RFC 6238 requires. A password alone never signs anyone in:
//! every sign-in with a built-in account also needs an authenticator code or
//! a single-use recovery code (docs/design.md section 7.1).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::{Mutex, OnceLock};

use aws_lc_rs::{constant_time, hmac, pbkdf2};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use warren_core::keys::{hex, random_bytes, sha256};
use zeroize::Zeroizing;

use crate::Error;

/// The issuer recorded for built-in accounts. Their subject is the
/// username, and policy names them `local:<username>`.
pub const LOCAL_ISSUER: &str = "local";

/// The shortest password accepted, in characters.
pub const PASSWORD_MIN_CHARS: usize = 12;
/// The longest password accepted, in characters.
pub const PASSWORD_MAX_CHARS: usize = 256;
/// PBKDF2-HMAC-SHA256 iterations for new password hashes. Each stored hash
/// records its own count, so raising this rehashes passwords as their
/// owners next sign in.
pub const PBKDF2_ITERATIONS: u32 = 600_000;
/// Stored hashes with fewer iterations than this are refused outright.
const PBKDF2_MIN_ITERATIONS: u32 = 100_000;
/// Nor are hashes with absurdly many, which would be a denial of service.
const PBKDF2_MAX_ITERATIONS: u32 = 10_000_000;
const PBKDF2_PREFIX: &str = "$pbkdf2-sha256$i=";

/// Authenticator codes: RFC 6238 defaults, which every authenticator app
/// supports.
pub const TOTP_PERIOD: i64 = 30;
const TOTP_DIGITS: u32 = 6;
/// Codes from one period either side of now are accepted, for clock drift
/// and typing time.
const TOTP_WINDOW: i64 = 1;
/// Bytes of a new authenticator secret (160 bits, RFC 4226 section 4).
const TOTP_SECRET_BYTES: usize = 20;

/// Recovery codes issued when an authenticator is enrolled.
pub const RECOVERY_CODES: usize = 10;

/// Consecutive failed sign-ins (password or code) that lock an account.
pub const MAX_FAILED_ATTEMPTS: i64 = 5;
/// How long a locked account stays locked, seconds.
pub const LOCKOUT_SECONDS: i64 = 15 * 60;
/// Failed sign-ins one source address may make per window, across every
/// account, before it is refused for the rest of the window.
pub const SOURCE_FAILURE_LIMIT: u32 = 20;
/// The window for [`SOURCE_FAILURE_LIMIT`], seconds.
pub const SOURCE_WINDOW_SECONDS: i64 = 15 * 60;

/// How long a setup link (first password, or one after a reset) stays
/// valid, seconds.
pub const SETUP_LINK_LIFETIME: i64 = 72 * 3600;

fn rng_error(e: impl std::fmt::Display) -> Error {
    Error::Internal(e.to_string())
}

/// Checks a new password: long enough, not absurdly long, and not the
/// username. Composition rules are deliberately absent (NIST SP 800-63B);
/// the authenticator code is what a guessed password still lacks.
pub fn check_new_password(password: &str, username: &str) -> Result<(), String> {
    let chars = password.chars().count();
    if chars < PASSWORD_MIN_CHARS {
        return Err(format!(
            "The password must be at least {PASSWORD_MIN_CHARS} characters long."
        ));
    }
    if chars > PASSWORD_MAX_CHARS {
        return Err(format!(
            "The password must be at most {PASSWORD_MAX_CHARS} characters long."
        ));
    }
    if password.chars().any(char::is_control) {
        return Err("The password cannot contain control characters.".into());
    }
    if password.trim().eq_ignore_ascii_case(username) {
        return Err("The password cannot be the username.".into());
    }
    Ok(())
}

/// Hashes a password with a fresh salt:
/// `$pbkdf2-sha256$i=<iterations>$<salt>$<hash>`, base64 without padding.
pub fn hash_password(password: &str) -> Result<String, Error> {
    hash_with(password, PBKDF2_ITERATIONS)
}

fn hash_with(password: &str, iterations: u32) -> Result<String, Error> {
    let salt: [u8; 16] = random_bytes().map_err(rng_error)?;
    let rounds = NonZeroU32::new(iterations).ok_or_else(|| Error::Internal("iterations".into()))?;
    let mut out = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        rounds,
        &salt,
        password.as_bytes(),
        &mut out,
    );
    Ok(format!(
        "{PBKDF2_PREFIX}{iterations}${}${}",
        STANDARD_NO_PAD.encode(salt),
        STANDARD_NO_PAD.encode(out)
    ))
}

fn parse_hash(encoded: &str) -> Option<(u32, Vec<u8>, Vec<u8>)> {
    let rest = encoded.strip_prefix(PBKDF2_PREFIX)?;
    let mut parts = rest.split('$');
    let (Some(i), Some(salt), Some(hash), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let iterations: u32 = i.parse().ok()?;
    if !(PBKDF2_MIN_ITERATIONS..=PBKDF2_MAX_ITERATIONS).contains(&iterations) {
        return None;
    }
    let salt = STANDARD_NO_PAD.decode(salt).ok()?;
    let hash = STANDARD_NO_PAD.decode(hash).ok()?;
    (salt.len() >= 16 && hash.len() == 32).then_some((iterations, salt, hash))
}

/// Whether `password` matches `encoded`, compared in constant time. A
/// malformed hash matches nothing.
pub fn verify_password(encoded: &str, password: &str) -> bool {
    let Some((iterations, salt, hash)) = parse_hash(encoded) else {
        return false;
    };
    let Some(rounds) = NonZeroU32::new(iterations) else {
        return false;
    };
    pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA256,
        rounds,
        &salt,
        password.as_bytes(),
        &hash,
    )
    .is_ok()
}

/// Whether a stored hash uses fewer iterations than new hashes do.
pub fn needs_rehash(encoded: &str) -> bool {
    parse_hash(encoded).is_none_or(|(i, _, _)| i < PBKDF2_ITERATIONS)
}

/// Spends as long as checking a real password, for usernames that do not
/// exist, so the response time does not tell which ones do.
pub fn verify_nothing(password: &str) {
    static DUMMY: OnceLock<Option<String>> = OnceLock::new();
    if let Some(dummy) = DUMMY.get_or_init(|| hash_password("no such account").ok()) {
        let _ = verify_password(dummy, password);
    }
}

/// A new authenticator secret.
pub fn new_totp_secret() -> Result<Zeroizing<Vec<u8>>, Error> {
    let bytes: [u8; TOTP_SECRET_BYTES] = random_bytes().map_err(rng_error)?;
    Ok(Zeroizing::new(bytes.to_vec()))
}

/// The authenticator code for one time step (RFC 4226 section 5.3).
pub fn totp_code(secret: &[u8], step: i64) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &step.to_be_bytes());
    let mac = tag.as_ref();
    let offset = usize::from(mac[mac.len() - 1] & 0x0f);
    let binary = u32::from_be_bytes([
        mac[offset] & 0x7f,
        mac[offset + 1],
        mac[offset + 2],
        mac[offset + 3],
    ]);
    binary % 10u32.pow(TOTP_DIGITS)
}

/// The time step at Unix time `now`.
pub fn totp_step(now: i64) -> i64 {
    now.div_euclid(TOTP_PERIOD)
}

/// Checks a six-digit authenticator code against the steps around `now`,
/// accepting only steps after `last_step`, so a code is never accepted
/// twice. Returns the step it matched.
pub fn verify_totp(secret: &[u8], code: &str, now: i64, last_step: i64) -> Option<i64> {
    if code.len() != TOTP_DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let current = totp_step(now);
    let mut matched = None;
    for step in (current - TOTP_WINDOW)..=(current + TOTP_WINDOW) {
        let expected = format!(
            "{:0width$}",
            totp_code(secret, step),
            width = TOTP_DIGITS as usize
        );
        let equal =
            constant_time::verify_slices_are_equal(expected.as_bytes(), code.as_bytes()).is_ok();
        if equal && step > last_step && matched.is_none() {
            matched = Some(step);
        }
    }
    matched
}

/// RFC 4648 base32 without padding, as authenticator apps expect secrets.
pub fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for b in bytes {
        buffer = (buffer << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// Percent-encodes everything but RFC 3986 unreserved characters.
fn percent(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// The `otpauth://` URI an authenticator app imports: the account shows
/// as `issuer:account`.
pub fn otpauth_uri(secret: &[u8], issuer: &str, account: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD}",
        percent(issuer),
        percent(account),
        base32(secret),
        percent(issuer),
    )
}

/// `text` as a QR code, an SVG image black on white with the standard
/// four-module quiet zone, for inline use in a page.
pub fn qr_svg(text: &str) -> Result<String, Error> {
    use qrcode::{Color, EcLevel, QrCode};
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M)
        .map_err(|e| Error::Internal(format!("QR code: {e}")))?;
    let width = code.width();
    let size = width + 8;
    // One subpath per horizontal run of dark modules.
    let colors = code.to_colors();
    let mut path = String::new();
    for (y, row) in colors.chunks(width).enumerate() {
        let mut x = 0;
        while x < width {
            if row[x] != Color::Dark {
                x += 1;
                continue;
            }
            let run = row[x..].iter().take_while(|c| **c == Color::Dark).count();
            let _ = write!(path, "M{} {}h{run}v1h-{run}z", x + 4, y + 4);
            x += run;
        }
    }
    Ok(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {size} {size}\" width=\"220\" height=\"220\" shape-rendering=\"crispEdges\" role=\"img\" aria-label=\"QR code for your authenticator app\"><rect width=\"{size}\" height=\"{size}\" fill=\"#fff\"/><path fill=\"#000\" d=\"{path}\"/></svg>"
    ))
}

/// New recovery codes, as shown to the user once: ten groups of
/// `xxxxx-xxxxx` from a 32-letter alphabet (50 bits each).
pub fn new_recovery_codes() -> Result<Vec<Zeroizing<String>>, Error> {
    (0..RECOVERY_CODES)
        .map(|_| {
            let bytes: [u8; 7] = random_bytes().map_err(rng_error)?;
            let letters = base32(&bytes).to_ascii_lowercase();
            Ok(Zeroizing::new(format!(
                "{}-{}",
                &letters[..5],
                &letters[5..10]
            )))
        })
        .collect()
}

/// A recovery code as typed, without spaces or dashes and lowercased, if
/// it could be one.
pub fn normalize_recovery_code(input: &str) -> Option<String> {
    let code: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_lowercase();
    (code.len() == 10 && code.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')))
        .then_some(code)
}

/// How a recovery code is stored. The codes carry 50 random bits, so a
/// plain digest suffices; they are also single use.
pub fn recovery_code_hash(normalized: &str) -> String {
    hex(&sha256(
        format!("warren recovery code {normalized}").as_bytes(),
    ))
}

/// Failed sign-ins per source address, so one source cannot guess
/// passwords across many accounts. IPv6 sources count per /64, since one
/// host can hold a whole /64. Kept in memory: a restart forgets it, and
/// each account's own lockout still holds.
#[derive(Default)]
pub struct SourceLimiter {
    failures: Mutex<HashMap<IpAddr, (i64, u32)>>,
}

fn source_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut octets = v6.octets();
                octets[8..].fill(0);
                IpAddr::V6(octets.into())
            }
        },
    }
}

impl SourceLimiter {
    /// Counts a sign-in attempt from `source` at `now` before it is
    /// checked, refusing it (false) once the window's limit is reached, so
    /// concurrent attempts cannot outrun the limit. Sources without an
    /// address (the local socket) are not limited.
    pub fn attempt(&self, source: Option<IpAddr>, now: i64) -> bool {
        let Some(ip) = source else { return true };
        let Ok(mut map) = self.failures.lock() else {
            return false;
        };
        if map.len() > 100_000 {
            map.retain(|_, (start, _)| now - *start < SOURCE_WINDOW_SECONDS);
        }
        let entry = map.entry(source_key(ip)).or_insert((now, 0));
        if now - entry.0 >= SOURCE_WINDOW_SECONDS {
            *entry = (now, 0);
        }
        if entry.1 >= SOURCE_FAILURE_LIMIT {
            return false;
        }
        entry.1 += 1;
        true
    }

    /// Takes back an attempt from `source` that succeeded.
    pub fn succeeded(&self, source: Option<IpAddr>, now: i64) {
        let Some(ip) = source else { return };
        let Ok(mut map) = self.failures.lock() else {
            return;
        };
        if let Some(entry) = map.get_mut(&source_key(ip))
            && now - entry.0 < SOURCE_WINDOW_SECONDS
        {
            entry.1 = entry.1.saturating_sub(1);
        }
    }
}

/// Failed sign-ins with usernames that are not built-in accounts, counted
/// and locked out exactly as accounts are, so the responses never tell
/// which usernames exist. Kept in memory by a digest of the name.
#[derive(Default)]
pub struct UnknownNames {
    attempts: Mutex<HashMap<[u8; 32], (i64, i64)>>,
}

impl UnknownNames {
    /// As [`crate::store::Store::reserve_local_attempt`]: `None` while the
    /// name is locked, otherwise the lock this attempt set (0 if none).
    pub fn attempt(&self, name: &str, now: i64) -> Option<i64> {
        let Ok(mut map) = self.attempts.lock() else {
            return None;
        };
        if map.len() > 100_000 {
            map.retain(|_, (_, locked_until)| *locked_until > now);
        }
        let (failed, locked_until) = map.entry(sha256(name.as_bytes())).or_insert((0, 0));
        if *locked_until > now {
            return None;
        }
        (*failed, *locked_until) = if *failed + 1 >= MAX_FAILED_ATTEMPTS {
            (0, now + LOCKOUT_SECONDS)
        } else {
            (*failed + 1, 0)
        };
        Some(*locked_until)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_hash_and_verify() {
        // Few iterations keep the test fast; the format and checks are
        // the same.
        let h = hash_with("correct horse battery", PBKDF2_MIN_ITERATIONS).unwrap();
        assert!(h.starts_with("$pbkdf2-sha256$i=100000$"));
        assert!(verify_password(&h, "correct horse battery"));
        assert!(!verify_password(&h, "correct horse batterY"));
        assert!(needs_rehash(&h));
        // Salted: the same password hashes differently each time.
        assert_ne!(
            h,
            hash_with("correct horse battery", PBKDF2_MIN_ITERATIONS).unwrap()
        );
        // Tampered or weakened hashes match nothing.
        for bad in [
            h.replace("i=100000", "i=1000"),
            h.replace("i=100000", "i=99999999"),
            h.replace("pbkdf2-sha256", "pbkdf2-sha1"),
            format!("{h}$x"),
            String::new(),
        ] {
            assert!(!verify_password(&bad, "correct horse battery"), "{bad}");
        }
    }

    #[test]
    fn the_production_cost_is_bounded() {
        let started = std::time::Instant::now();
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.contains(&format!("i={PBKDF2_ITERATIONS}$")));
        assert!(!needs_rehash(&h));
        assert!(verify_password(&h, "correct horse battery"));
        eprintln!("hash and verify: {:?}", started.elapsed());
    }

    #[test]
    fn new_passwords_are_checked() {
        assert!(check_new_password("short", "ada").is_err());
        assert!(check_new_password(&"x".repeat(257), "ada").is_err());
        assert!(check_new_password("ada-lovelace-1", "ada-lovelace-1").is_err());
        assert!(check_new_password("tab\tinside-password", "ada").is_err());
        assert!(check_new_password("twelve chars", "ada").is_ok());
        // Characters, not bytes.
        assert!(check_new_password("ééééééééééé", "ada").is_err());
        assert!(check_new_password("éééééééééééé", "ada").is_ok());
    }

    #[test]
    fn totp_matches_rfc_6238() {
        // RFC 6238 appendix B, SHA-1 seed, last six digits.
        let secret = b"12345678901234567890";
        for (time, code) in [
            (59, 287_082),
            (1_111_111_109, 81_804),
            (1_111_111_111, 50_471),
            (1_234_567_890, 5_924),
            (2_000_000_000, 279_037),
            (20_000_000_000, 353_130),
        ] {
            assert_eq!(totp_code(secret, totp_step(time)), code, "time {time}");
        }
        // RFC 4648 test vectors.
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32(b"fooba"), "MZXW6YTB");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(secret), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    #[test]
    fn totp_codes_are_accepted_once_and_near_now() {
        let secret = b"12345678901234567890";
        let now = 1_111_111_111;
        let step = totp_step(now);
        let code = |s: i64| format!("{:06}", totp_code(secret, s));
        assert_eq!(verify_totp(secret, &code(step), now, 0), Some(step));
        assert_eq!(verify_totp(secret, &code(step - 1), now, 0), Some(step - 1));
        assert_eq!(verify_totp(secret, &code(step + 1), now, 0), Some(step + 1));
        assert_eq!(verify_totp(secret, &code(step - 2), now, 0), None);
        assert_eq!(verify_totp(secret, &code(step + 2), now, 0), None);
        // A code is never accepted twice, nor one older than the last.
        assert_eq!(verify_totp(secret, &code(step), now, step), None);
        assert_eq!(verify_totp(secret, &code(step - 1), now, step), None);
        assert_eq!(
            verify_totp(secret, &code(step + 1), now, step),
            Some(step + 1)
        );
        for bad in ["", "12345", "1234567", "12345a", " 12345"] {
            assert_eq!(verify_totp(secret, bad, now, 0), None, "{bad:?}");
        }
    }

    #[test]
    fn otpauth_uris_and_qr_codes() {
        let uri = otpauth_uri(b"12345678901234567890", "warren example.com", "ada");
        assert_eq!(
            uri,
            "otpauth://totp/warren%20example.com:ada?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=warren%20example.com&algorithm=SHA1&digits=6&period=30"
        );
        let svg = qr_svg(&uri).unwrap();
        assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
        // Version 8 at level M holds this URI: 49 modules plus the quiet zone.
        assert!(svg.contains("viewBox=\"0 0 57 57\""), "{svg}");
        // The top-left finder pattern's first row is seven dark modules.
        assert!(svg.contains("M4 4h7v1h-7z"), "{svg}");
    }

    #[test]
    fn recovery_codes() {
        let codes = new_recovery_codes().unwrap();
        assert_eq!(codes.len(), RECOVERY_CODES);
        let first = codes[0].to_string();
        assert_eq!(first.len(), 11);
        assert_eq!(&first[5..6], "-");
        let typed = format!(" {} ", first.to_ascii_uppercase().replace('-', " - "));
        let normalized = normalize_recovery_code(&typed).unwrap();
        assert_eq!(normalized, first.replace('-', ""));
        assert_eq!(recovery_code_hash(&normalized).len(), 64);
        assert!(normalize_recovery_code("123456").is_none());
        assert!(normalize_recovery_code("abcde-abcd1").is_none());
        let unique: std::collections::BTreeSet<String> =
            codes.iter().map(|c| c.to_string()).collect();
        assert_eq!(unique.len(), RECOVERY_CODES);
    }

    #[test]
    fn sources_are_limited_per_window() {
        let limiter = SourceLimiter::default();
        let a: IpAddr = "203.0.113.7".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:3:4:5:6".parse().unwrap();
        let b_neighbor: IpAddr = "2001:db8:1:2:ffff::1".parse().unwrap();
        for _ in 0..SOURCE_FAILURE_LIMIT {
            assert!(limiter.attempt(Some(a), 1_000));
            assert!(limiter.attempt(Some(b), 1_000));
        }
        assert!(!limiter.attempt(Some(a), 1_001));
        // One /64 is one source.
        assert!(!limiter.attempt(Some(b_neighbor), 1_001));
        assert!(limiter.attempt(Some("203.0.113.8".parse().unwrap()), 1_001));
        // A success gives its attempt back.
        limiter.succeeded(Some(a), 1_001);
        assert!(limiter.attempt(Some(a), 1_001));
        assert!(!limiter.attempt(Some(a), 1_001));
        // The window passes.
        assert!(limiter.attempt(Some(a), 1_000 + SOURCE_WINDOW_SECONDS));
        assert!(limiter.attempt(Some(a), 1_001 + SOURCE_WINDOW_SECONDS));
        assert!(limiter.attempt(None, 0));
    }

    #[test]
    fn unknown_names_lock_like_accounts() {
        let names = UnknownNames::default();
        for _ in 1..MAX_FAILED_ATTEMPTS {
            assert_eq!(names.attempt("nobody", 1_000), Some(0));
        }
        assert_eq!(
            names.attempt("nobody", 1_000),
            Some(1_000 + LOCKOUT_SECONDS)
        );
        assert_eq!(names.attempt("nobody", 1_001), None);
        assert_eq!(names.attempt("somebody", 1_001), Some(0));
        assert_eq!(names.attempt("nobody", 1_000 + LOCKOUT_SECONDS), Some(0));
    }
}
