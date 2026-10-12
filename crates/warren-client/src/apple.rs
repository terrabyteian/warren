//! The macOS Security framework, reached directly through its C API: the
//! device key in the Secure Enclave, secrets in the login keychain, and the
//! system's certificate trust evaluation. A handful of functions is all the
//! client needs, so they are declared here rather than pulled in through
//! binding crates; every call is a thin, checked wrapper, and every object
//! the framework returns is released exactly once by [`Cf`].
//!
//! None of this needs an entitlement or a code signature beyond the ad-hoc
//! one every arm64 binary carries: a Secure Enclave key that is not stored
//! in the keychain is represented by an opaque blob that only this device's
//! Secure Enclave can use (the same value CryptoKit calls
//! `dataRepresentation`), and the login keychain is the file-based one that
//! unsigned tools may use.
#![allow(unsafe_code)]

use std::ffi::{c_char, c_void};
use std::ptr;
use std::sync::Mutex;

type CFTypeRef = *const c_void;
type CFIndex = isize;
type CFOptionFlags = usize;
type OSStatus = i32;
type Boolean = u8;

#[repr(C)]
struct CFDictionaryKeyCallBacks {
    _private: [u8; 0],
}

#[repr(C)]
struct CFDictionaryValueCallBacks {
    _private: [u8; 0],
}

#[repr(C)]
struct CFArrayCallBacks {
    _private: [u8; 0],
}

const UTF8: u32 = 0x0800_0100;
const NUMBER_SINT32: CFIndex = 3;
const ERR_ITEM_NOT_FOUND: OSStatus = -25300;
/// `kSecAccessControlPrivateKeyUsage`: the key may sign.
const PRIVATE_KEY_USAGE: CFOptionFlags = 1 << 30;

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFTypeDictionaryKeyCallBacks: CFDictionaryKeyCallBacks;
    static kCFTypeDictionaryValueCallBacks: CFDictionaryValueCallBacks;
    static kCFTypeArrayCallBacks: CFArrayCallBacks;
    static kCFBooleanTrue: CFTypeRef;
    static kCFBooleanFalse: CFTypeRef;

    fn CFRelease(cf: CFTypeRef);
    fn CFDictionaryCreateMutable(
        allocator: CFTypeRef,
        capacity: CFIndex,
        keys: *const CFDictionaryKeyCallBacks,
        values: *const CFDictionaryValueCallBacks,
    ) -> CFTypeRef;
    fn CFDictionarySetValue(dict: CFTypeRef, key: CFTypeRef, value: CFTypeRef);
    fn CFDictionaryGetValue(dict: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
    fn CFDataCreate(allocator: CFTypeRef, bytes: *const u8, length: CFIndex) -> CFTypeRef;
    fn CFDataGetLength(data: CFTypeRef) -> CFIndex;
    fn CFDataGetBytePtr(data: CFTypeRef) -> *const u8;
    fn CFStringCreateWithBytes(
        allocator: CFTypeRef,
        bytes: *const u8,
        length: CFIndex,
        encoding: u32,
        external: Boolean,
    ) -> CFTypeRef;
    fn CFStringGetCString(
        string: CFTypeRef,
        buffer: *mut c_char,
        size: CFIndex,
        encoding: u32,
    ) -> Boolean;
    fn CFNumberCreate(allocator: CFTypeRef, kind: CFIndex, value: *const c_void) -> CFTypeRef;
    fn CFArrayCreate(
        allocator: CFTypeRef,
        values: *const CFTypeRef,
        count: CFIndex,
        callbacks: *const CFArrayCallBacks,
    ) -> CFTypeRef;
    fn CFErrorGetCode(error: CFTypeRef) -> CFIndex;
    fn CFErrorCopyDescription(error: CFTypeRef) -> CFTypeRef;
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecAttrKeyType: CFTypeRef;
    static kSecAttrKeyTypeECSECPrimeRandom: CFTypeRef;
    static kSecAttrKeySizeInBits: CFTypeRef;
    static kSecAttrTokenID: CFTypeRef;
    static kSecAttrTokenIDSecureEnclave: CFTypeRef;
    static kSecPrivateKeyAttrs: CFTypeRef;
    static kSecAttrIsPermanent: CFTypeRef;
    static kSecAttrAccessControl: CFTypeRef;
    static kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly: CFTypeRef;
    static kSecAttrKeyClass: CFTypeRef;
    static kSecAttrKeyClassPrivate: CFTypeRef;
    static kSecKeyAlgorithmECDSASignatureMessageX962SHA256: CFTypeRef;
    static kSecClass: CFTypeRef;
    static kSecClassGenericPassword: CFTypeRef;
    static kSecAttrService: CFTypeRef;
    static kSecAttrAccount: CFTypeRef;
    static kSecAttrLabel: CFTypeRef;
    static kSecValueData: CFTypeRef;
    static kSecReturnData: CFTypeRef;
    static kSecMatchLimit: CFTypeRef;
    static kSecMatchLimitOne: CFTypeRef;

    fn SecAccessControlCreateWithFlags(
        allocator: CFTypeRef,
        protection: CFTypeRef,
        flags: CFOptionFlags,
        error: *mut CFTypeRef,
    ) -> CFTypeRef;
    fn SecKeyCreateRandomKey(parameters: CFTypeRef, error: *mut CFTypeRef) -> CFTypeRef;
    fn SecKeyCreateWithData(
        data: CFTypeRef,
        attributes: CFTypeRef,
        error: *mut CFTypeRef,
    ) -> CFTypeRef;
    fn SecKeyCopyAttributes(key: CFTypeRef) -> CFTypeRef;
    fn SecKeyCopyPublicKey(key: CFTypeRef) -> CFTypeRef;
    fn SecKeyCopyExternalRepresentation(key: CFTypeRef, error: *mut CFTypeRef) -> CFTypeRef;
    fn SecKeyCreateSignature(
        key: CFTypeRef,
        algorithm: CFTypeRef,
        data: CFTypeRef,
        error: *mut CFTypeRef,
    ) -> CFTypeRef;
    fn SecItemAdd(attributes: CFTypeRef, result: *mut CFTypeRef) -> OSStatus;
    fn SecItemCopyMatching(query: CFTypeRef, result: *mut CFTypeRef) -> OSStatus;
    fn SecItemDelete(query: CFTypeRef) -> OSStatus;
    fn SecCopyErrorMessageString(status: OSStatus, reserved: *const c_void) -> CFTypeRef;
    fn SecCertificateCreateWithData(allocator: CFTypeRef, data: CFTypeRef) -> CFTypeRef;
    fn SecPolicyCreateSSL(server: Boolean, hostname: CFTypeRef) -> CFTypeRef;
    fn SecTrustCreateWithCertificates(
        certificates: CFTypeRef,
        policies: CFTypeRef,
        trust: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecTrustEvaluateWithError(trust: CFTypeRef, error: *mut CFTypeRef) -> bool;
}

/// An owned Core Foundation object, released when dropped.
struct Cf(CFTypeRef);

impl Cf {
    /// Takes ownership of an object the framework returned under the
    /// Create or Copy rule; `None` when it returned NULL.
    fn take(obj: CFTypeRef) -> Option<Cf> {
        (!obj.is_null()).then_some(Cf(obj))
    }

    fn get(&self) -> CFTypeRef {
        self.0
    }
}

impl Drop for Cf {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a non-NULL object we own one reference to
        // (Create/Copy rule), released exactly once here.
        unsafe { CFRelease(self.0) }
    }
}

fn data(bytes: &[u8]) -> Result<Cf, String> {
    // SAFETY: `bytes` is readable for its length; CFDataCreate copies it.
    Cf::take(unsafe { CFDataCreate(ptr::null(), bytes.as_ptr(), bytes.len() as CFIndex) })
        .ok_or_else(|| "out of memory".to_owned())
}

/// The bytes of a CFData. The caller guarantees `obj` is a CFData.
fn data_bytes(obj: CFTypeRef) -> Vec<u8> {
    // SAFETY: `obj` is a live CFData; the pointer and length describe its
    // contents, which are copied before the object can change or go away.
    unsafe {
        let len = CFDataGetLength(obj);
        let p = CFDataGetBytePtr(obj);
        if p.is_null() || len <= 0 {
            return Vec::new();
        }
        std::slice::from_raw_parts(p, len as usize).to_vec()
    }
}

fn string(s: &str) -> Result<Cf, String> {
    // SAFETY: `s` is valid UTF-8, readable for its length; the string is
    // copied.
    Cf::take(unsafe {
        CFStringCreateWithBytes(ptr::null(), s.as_ptr(), s.len() as CFIndex, UTF8, 0)
    })
    .ok_or_else(|| "out of memory".to_owned())
}

fn to_string(obj: CFTypeRef) -> String {
    let mut buf = vec![0 as c_char; 4096];
    // SAFETY: `obj` is a live CFString and `buf` is writable for its
    // length; the result is NUL-terminated on success.
    let ok = unsafe { CFStringGetCString(obj, buf.as_mut_ptr(), buf.len() as CFIndex, UTF8) };
    if ok == 0 {
        return String::new();
    }
    let bytes: Vec<u8> = buf
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Describes a CFError the framework handed us, and releases it.
fn error_text(error: CFTypeRef) -> String {
    let Some(error) = Cf::take(error) else {
        return "unknown error".into();
    };
    // SAFETY: `error` is a live CFError.
    let code = unsafe { CFErrorGetCode(error.get()) };
    // SAFETY: as above; the description follows the Copy rule.
    match Cf::take(unsafe { CFErrorCopyDescription(error.get()) }) {
        Some(d) => format!("{} ({code})", to_string(d.get())),
        None => format!("error {code}"),
    }
}

fn status_text(status: OSStatus) -> String {
    // SAFETY: the message follows the Copy rule and may be NULL.
    match Cf::take(unsafe { SecCopyErrorMessageString(status, ptr::null()) }) {
        Some(m) => format!("{} ({status})", to_string(m.get())),
        None => format!("OSStatus {status}"),
    }
}

/// A mutable CFDictionary with CF-retaining callbacks: values set on it are
/// retained by the dictionary, so our own references can be dropped.
struct Dict(Cf);

impl Dict {
    fn new() -> Result<Dict, String> {
        // SAFETY: the callbacks are the framework's own constants.
        let d = unsafe {
            CFDictionaryCreateMutable(
                ptr::null(),
                0,
                &raw const kCFTypeDictionaryKeyCallBacks,
                &raw const kCFTypeDictionaryValueCallBacks,
            )
        };
        Cf::take(d)
            .map(Dict)
            .ok_or_else(|| "out of memory".to_owned())
    }

    fn set(&self, key: CFTypeRef, value: CFTypeRef) {
        // SAFETY: the dictionary is live and mutable, and `key` and `value`
        // are live CF objects, retained by the dictionary's callbacks.
        unsafe { CFDictionarySetValue(self.0.get(), key, value) }
    }

    fn get(&self) -> CFTypeRef {
        self.0.get()
    }
}

/// A P-256 private key generated in and held by the Secure Enclave. It
/// never leaves the enclave: this process holds only a reference to it,
/// and storage holds only the enclave-wrapped blob.
pub struct SecureEnclaveKey {
    key: Mutex<Cf>,
    public: [u8; 65],
}

// SAFETY: the key is an immutable SecKey reference; the only operation on
// it after construction is signing, which the mutex serializes, so the
// reference is never used from two threads at once.
unsafe impl Send for SecureEnclaveKey {}
// SAFETY: as above; shared access goes through the mutex.
unsafe impl Sync for SecureEnclaveKey {}

impl std::fmt::Debug for SecureEnclaveKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecureEnclaveKey")
    }
}

/// The attribute that carries a Secure Enclave key's wrapped blob
/// (`kSecAttrTokenOID`, which the SDK does not export by name).
const TOKEN_OID: &str = "toid";

impl SecureEnclaveKey {
    /// Generates a key in the Secure Enclave, usable after the first unlock
    /// since boot, so an always-on tunnel can renew its certificate while
    /// the screen is locked. Returns the key and the blob that loads it
    /// again on this device; the blob is useless anywhere else.
    pub fn generate() -> Result<(SecureEnclaveKey, Vec<u8>), String> {
        let mut err: CFTypeRef = ptr::null();
        // SAFETY: the protection class is the framework's constant; `err`
        // receives a CFError on failure.
        let access = Cf::take(unsafe {
            SecAccessControlCreateWithFlags(
                ptr::null(),
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                PRIVATE_KEY_USAGE,
                &mut err,
            )
        })
        .ok_or_else(|| error_text(err))?;
        let bits: i32 = 256;
        // SAFETY: `bits` is a live i32 matching the number type.
        let size = Cf::take(unsafe {
            CFNumberCreate(ptr::null(), NUMBER_SINT32, (&raw const bits).cast())
        })
        .ok_or("out of memory")?;
        let private = Dict::new()?;
        // SAFETY (all `set` calls below): framework constants and live
        // objects only.
        unsafe {
            private.set(kSecAttrIsPermanent, kCFBooleanFalse);
            private.set(kSecAttrAccessControl, access.get());
        }
        let params = Dict::new()?;
        // SAFETY: as above.
        unsafe {
            params.set(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
            params.set(kSecAttrKeySizeInBits, size.get());
            params.set(kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
            params.set(kSecPrivateKeyAttrs, private.get());
        }
        let mut err: CFTypeRef = ptr::null();
        // SAFETY: `params` is a live dictionary; `err` receives a CFError.
        let key = Cf::take(unsafe { SecKeyCreateRandomKey(params.get(), &mut err) })
            .ok_or_else(|| error_text(err))?;
        // SAFETY: `key` is a live SecKey; the attributes follow the Copy
        // rule.
        let attrs = Cf::take(unsafe { SecKeyCopyAttributes(key.get()) })
            .ok_or("the Secure Enclave key has no attributes")?;
        let name = string(TOKEN_OID)?;
        // SAFETY: Get rule: the value is borrowed from `attrs`, which
        // outlives its use here.
        let blob = unsafe { CFDictionaryGetValue(attrs.get(), name.get()) };
        if blob.is_null() {
            return Err("the Secure Enclave did not return a key blob".into());
        }
        let blob = data_bytes(blob);
        let public = public_point(&key)?;
        Ok((
            SecureEnclaveKey {
                key: Mutex::new(key),
                public,
            },
            blob,
        ))
    }

    /// Loads a key from the blob [`SecureEnclaveKey::generate`] returned.
    /// Fails on any other device, or if the blob was altered.
    pub fn load(blob: &[u8]) -> Result<SecureEnclaveKey, String> {
        let attrs = Dict::new()?;
        let name = string(TOKEN_OID)?;
        let blob = data(blob)?;
        // SAFETY: framework constants and live objects.
        unsafe {
            attrs.set(kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
            attrs.set(kSecAttrKeyClass, kSecAttrKeyClassPrivate);
            attrs.set(kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
            attrs.set(name.get(), blob.get());
        }
        let empty = data(&[])?;
        let mut err: CFTypeRef = ptr::null();
        // SAFETY: live objects; `err` receives a CFError on failure.
        let key = Cf::take(unsafe { SecKeyCreateWithData(empty.get(), attrs.get(), &mut err) })
            .ok_or_else(|| error_text(err))?;
        let public = public_point(&key)?;
        Ok(SecureEnclaveKey {
            key: Mutex::new(key),
            public,
        })
    }

    /// The public key as an uncompressed point.
    pub fn public_point(&self) -> &[u8; 65] {
        &self.public
    }

    /// Signs `message` with ECDSA P-256 and SHA-256 in the enclave; the
    /// signature is DER.
    pub fn sign_der(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let msg = data(message)?;
        let key = self.key.lock().map_err(|_| "key lock poisoned")?;
        let mut err: CFTypeRef = ptr::null();
        // SAFETY: live key and data; the algorithm is the framework's
        // constant; `err` receives a CFError on failure.
        let sig = Cf::take(unsafe {
            SecKeyCreateSignature(
                key.get(),
                kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                msg.get(),
                &mut err,
            )
        })
        .ok_or_else(|| error_text(err))?;
        Ok(data_bytes(sig.get()))
    }
}

fn public_point(key: &Cf) -> Result<[u8; 65], String> {
    // SAFETY: `key` is a live SecKey; Copy rule.
    let public =
        Cf::take(unsafe { SecKeyCopyPublicKey(key.get()) }).ok_or("the key has no public half")?;
    let mut err: CFTypeRef = ptr::null();
    // SAFETY: live public key; Copy rule; `err` receives a CFError.
    let rep = Cf::take(unsafe { SecKeyCopyExternalRepresentation(public.get(), &mut err) })
        .ok_or_else(|| error_text(err))?;
    data_bytes(rep.get())
        .try_into()
        .map_err(|_| "the public key is not an uncompressed P-256 point".into())
}

/// The login keychain's generic password items.
pub mod keychain {
    use super::*;

    fn query(service: &str, account: &str) -> Result<(Dict, Cf, Cf), String> {
        let q = Dict::new()?;
        let service = string(service)?;
        let account = string(account)?;
        // SAFETY: framework constants and live strings.
        unsafe {
            q.set(kSecClass, kSecClassGenericPassword);
            q.set(kSecAttrService, service.get());
            q.set(kSecAttrAccount, account.get());
        }
        Ok((q, service, account))
    }

    /// Stores `secret`, replacing any item with the same service and
    /// account.
    pub fn set(service: &str, account: &str, label: &str, secret: &[u8]) -> Result<(), String> {
        delete(service, account)?;
        let (q, _service, _account) = query(service, account)?;
        let value = data(secret)?;
        let label = string(label)?;
        // SAFETY: framework constants and live objects.
        unsafe {
            q.set(kSecValueData, value.get());
            q.set(kSecAttrLabel, label.get());
        }
        // SAFETY: a live attribute dictionary; no result is requested.
        let status = unsafe { SecItemAdd(q.get(), ptr::null_mut()) };
        if status != 0 {
            return Err(format!(
                "cannot store the key in the login keychain: {}",
                status_text(status)
            ));
        }
        Ok(())
    }

    /// The secret stored for the service and account, if any.
    pub fn get(service: &str, account: &str) -> Result<Option<Vec<u8>>, String> {
        let (q, _service, _account) = query(service, account)?;
        // SAFETY: framework constants.
        unsafe {
            q.set(kSecReturnData, kCFBooleanTrue);
            q.set(kSecMatchLimit, kSecMatchLimitOne);
        }
        let mut out: CFTypeRef = ptr::null();
        // SAFETY: a live query; `out` receives a CFData under the Copy rule.
        let status = unsafe { SecItemCopyMatching(q.get(), &mut out) };
        match status {
            0 => {
                let out = Cf::take(out).ok_or("the keychain returned no data")?;
                Ok(Some(data_bytes(out.get())))
            }
            ERR_ITEM_NOT_FOUND => Ok(None),
            s => Err(format!(
                "cannot read the key from the login keychain: {}",
                status_text(s)
            )),
        }
    }

    /// Deletes the item, if there is one.
    pub fn delete(service: &str, account: &str) -> Result<(), String> {
        let (q, _service, _account) = query(service, account)?;
        // SAFETY: a live query.
        match unsafe { SecItemDelete(q.get()) } {
            0 | ERR_ITEM_NOT_FOUND => Ok(()),
            s => Err(format!(
                "cannot delete the key from the login keychain: {}",
                status_text(s)
            )),
        }
    }
}

/// Evaluates a server certificate chain (leaf first, DER) for TLS to
/// `hostname` against the system's trust settings: its roots, any root an
/// MDM profile or the user trusts, and their revocation and policy rules.
pub fn evaluate_server_trust(chain: &[&[u8]], hostname: &str) -> Result<(), String> {
    let mut certs = Vec::with_capacity(chain.len());
    for der in chain {
        let d = data(der)?;
        // SAFETY: a live CFData holding DER; Create rule; NULL if malformed.
        let cert = Cf::take(unsafe { SecCertificateCreateWithData(ptr::null(), d.get()) })
            .ok_or("a certificate in the chain is malformed")?;
        certs.push(cert);
    }
    let refs: Vec<CFTypeRef> = certs.iter().map(Cf::get).collect();
    // SAFETY: `refs` holds live certificates, retained by the array.
    let array = Cf::take(unsafe {
        CFArrayCreate(
            ptr::null(),
            refs.as_ptr(),
            refs.len() as CFIndex,
            &raw const kCFTypeArrayCallBacks,
        )
    })
    .ok_or("out of memory")?;
    let host = string(hostname)?;
    // SAFETY: a live host name string; Create rule.
    let policy = Cf::take(unsafe { SecPolicyCreateSSL(1, host.get()) }).ok_or("out of memory")?;
    let mut trust: CFTypeRef = ptr::null();
    // SAFETY: live array and policy; `trust` receives a SecTrust under the
    // Create rule.
    let status = unsafe { SecTrustCreateWithCertificates(array.get(), policy.get(), &mut trust) };
    if status != 0 {
        return Err(status_text(status));
    }
    let trust = Cf::take(trust).ok_or("no trust object")?;
    let mut err: CFTypeRef = ptr::null();
    // SAFETY: a live SecTrust; `err` receives a CFError on failure.
    if unsafe { SecTrustEvaluateWithError(trust.get(), &mut err) } {
        Ok(())
    } else {
        Err(error_text(err))
    }
}

/// The macOS version, for example `15.4.1`, from the system's version file.
pub fn os_version() -> String {
    let text = std::fs::read_to_string("/System/Library/CoreServices/SystemVersion.plist")
        .unwrap_or_default();
    // The file is a small XML plist: the value follows its key.
    text.split("<key>ProductVersion</key>")
        .nth(1)
        .and_then(|rest| rest.split("<string>").nth(1))
        .and_then(|rest| rest.split("</string>").next())
        .unwrap_or_default()
        .trim()
        .to_owned()
}

/// The hardware model identifier, for example `Mac16,1`.
pub fn hardware_model() -> String {
    sysctl_string(c"hw.model")
}

/// The host name, for display.
pub fn hostname() -> String {
    sysctl_string(c"kern.hostname")
}

fn sysctl_string(name: &std::ffi::CStr) -> String {
    let mut buf = [0u8; 256];
    let mut len = buf.len();
    // SAFETY: `name` is NUL-terminated; `buf` is writable for `len` bytes
    // and `len` is updated with the length written.
    let rc = unsafe {
        sysctlbyname(
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            &mut len,
            ptr::null(),
            0,
        )
    };
    if rc != 0 {
        return String::new();
    }
    let end = buf[..len].iter().position(|b| *b == 0).unwrap_or(len);
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

unsafe extern "C" {
    fn sysctlbyname(
        name: *const c_char,
        oldp: *mut c_void,
        oldlenp: *mut usize,
        newp: *const c_void,
        newlen: usize,
    ) -> std::ffi::c_int;
}
