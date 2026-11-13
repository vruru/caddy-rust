// server_tickets.rs
// Requires: openssl = "0.10.82", openssl-sys = "0.9.118", foreign-types = "0.3", zeroize

use foreign_types::ForeignTypeRef;
use openssl::error::ErrorStack;
use openssl::ex_data::Index;
use openssl::ssl::{SslContext, SslContextBuilder, SslOptions, SslRef, SslSessionCacheMode};
use openssl_sys as sys;
use std::ffi::{CStr, c_char, c_int, c_uchar, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use zeroize::Zeroizing;

// FFI Declarations for missing bindings
unsafe extern "C" {
    fn SSL_CTX_set_tlsext_ticket_key_evp_cb(
        ctx: *mut sys::SSL_CTX,
        cb: extern "C" fn(
            *mut sys::SSL,
            *mut c_uchar,
            *mut c_uchar,
            *mut sys::EVP_CIPHER_CTX,
            *mut sys::EVP_MAC_CTX,
            c_int,
        ) -> c_int,
    ) -> c_int;

    fn SSL_CTX_set_session_ticket_cb(
        ctx: *mut sys::SSL_CTX,
        generate: extern "C" fn(*mut sys::SSL, *mut c_void) -> c_int,
        dec: extern "C" fn(
            *mut sys::SSL,
            *mut sys::SSL_SESSION,
            *const c_uchar,
            usize,
            c_int,
            *mut c_void,
        ) -> c_int,
        arg: *mut c_void,
    ) -> c_int;

    fn SSL_SESSION_set1_ticket_appdata(
        s: *mut sys::SSL_SESSION,
        data: *const c_void,
        len: usize,
    ) -> c_int;
    fn SSL_SESSION_get0_ticket_appdata(
        s: *mut sys::SSL_SESSION,
        data: *mut *mut c_void,
        len: *mut usize,
    ) -> c_int;

    fn OSSL_PARAM_construct_utf8_string(
        key: *const c_char,
        data: *mut c_char,
        bsize: usize,
    ) -> sys::OSSL_PARAM;
}

// Constants
const TICKET_KEY_NAME_LEN: usize = 16;
const AES_KEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const MAX_SEALED_SIZE: usize = 256;
const PAYLOAD_LEN: usize = 8;
// Key struct
pub struct TicketKey {
    id: [u8; TICKET_KEY_NAME_LEN],
    enc: Zeroizing<[u8; AES_KEY_LEN]>,
    mac: Zeroizing<[u8; AES_KEY_LEN]>,
}

impl TicketKey {
    pub fn new(
        id: [u8; TICKET_KEY_NAME_LEN],
        enc: Zeroizing<[u8; AES_KEY_LEN]>,
        mac: Zeroizing<[u8; AES_KEY_LEN]>,
    ) -> Self {
        Self { id, enc, mac }
    }
}

pub trait ServerTicketProvider: Send + Sync {
    fn key(&self, requested: Option<&[u8; TICKET_KEY_NAME_LEN]>) -> Option<(TicketKey, bool)>;
    fn seal(&self, plain: &[u8]) -> Option<Vec<u8>>;
    fn open(&self, sealed: &[u8]) -> Option<Vec<u8>>;
}

struct State {
    provider: Arc<dyn ServerTicketProvider>,
    resumed_group: AtomicI64,
    issue_ok: AtomicBool,
}

#[derive(Clone)]
pub struct ServerTickets {
    inner: Arc<State>,
}

static INDEX: OnceLock<Index<SslContext, Arc<State>>> = OnceLock::new();
static INIT: Mutex<()> = Mutex::new(());
fn get_index() -> Result<Index<SslContext, Arc<State>>, ErrorStack> {
    if let Some(v) = INDEX.get() {
        return Ok(*v);
    }
    let _lock = INIT.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(v) = INDEX.get() {
        return Ok(*v);
    }
    let value = SslContext::new_ex_index()?;
    let _ = INDEX.set(value);
    Ok(value)
}

extern "C" fn key_cb(
    ssl_ptr: *mut sys::SSL,
    name: *mut c_uchar,
    iv: *mut c_uchar,
    cipher_ctx: *mut sys::EVP_CIPHER_CTX,
    mac_ctx: *mut sys::EVP_MAC_CTX,
    enc: c_int,
) -> c_int {
    let result = catch_unwind(AssertUnwindSafe(|| {
        key_cb_impl(ssl_ptr, name, iv, cipher_ctx, mac_ctx, enc)
    }));
    match result {
        Ok(v) => v,
        Err(_) => -1,
    }
}

fn key_cb_impl(
    ssl_ptr: *mut sys::SSL,
    name: *mut c_uchar,
    iv: *mut c_uchar,
    cipher_ctx: *mut sys::EVP_CIPHER_CTX,
    mac_ctx: *mut sys::EVP_MAC_CTX,
    enc: c_int,
) -> c_int {
    if ssl_ptr.is_null()
        || name.is_null()
        || iv.is_null()
        || cipher_ctx.is_null()
        || mac_ctx.is_null()
    {
        return -1;
    }
    let ssl = unsafe { SslRef::from_ptr(ssl_ptr) };
    let ctx = ssl.ssl_context();
    let index = match get_index() {
        Ok(i) => i,
        Err(_) => return -1,
    };
    let state = match ctx.ex_data(index) {
        Some(s) => s,
        None => return -1,
    };

    if enc == 1 {
        if !state.issue_ok.load(Ordering::SeqCst) {
            return 0;
        }
        if let Some((key, _)) = state.provider.key(None) {
            unsafe {
                std::ptr::copy_nonoverlapping(key.id.as_ptr(), name, TICKET_KEY_NAME_LEN);
                if sys::RAND_bytes(iv as *mut c_uchar, IV_LEN as c_int) != 1 {
                    return -1;
                }
                let cipher = sys::EVP_aes_256_cbc();
                if sys::EVP_EncryptInit_ex(
                    cipher_ctx,
                    cipher,
                    std::ptr::null_mut(),
                    key.enc.as_ptr(),
                    iv,
                ) != 1
                {
                    return -1;
                }
            }
            return if init_mac(mac_ctx, key.mac.as_ref()) == 1 {
                1
            } else {
                -1
            };
        }
        return 0;
    } else if enc == 0 {
        let mut requested_id = [0u8; TICKET_KEY_NAME_LEN];
        unsafe {
            std::ptr::copy_nonoverlapping(name, requested_id.as_mut_ptr(), TICKET_KEY_NAME_LEN);
        }
        if let Some((key, current)) = state.provider.key(Some(&requested_id)) {
            unsafe {
                if sys::EVP_DecryptInit_ex(
                    cipher_ctx,
                    sys::EVP_aes_256_cbc(),
                    std::ptr::null_mut(),
                    key.enc.as_ptr(),
                    iv,
                ) != 1
                {
                    return -1;
                }
            }
            if init_mac(mac_ctx, key.mac.as_ref()) != 1 {
                return -1;
            }
            return if current { 1 } else { 2 };
        }
        return 0;
    }
    -1
}

fn init_mac(mac_ctx: *mut sys::EVP_MAC_CTX, key: &[u8]) -> c_int {
    unsafe {
        let k_name = CStr::from_bytes_with_nul_unchecked(b"key\0");
        let d_name = CStr::from_bytes_with_nul_unchecked(b"digest\0");
        let d_val = CStr::from_bytes_with_nul_unchecked(b"SHA256\0");

        let params = [
            sys::OSSL_PARAM_construct_octet_string(
                k_name.as_ptr(),
                key.as_ptr() as *mut c_void,
                key.len(),
            ),
            OSSL_PARAM_construct_utf8_string(d_name.as_ptr(), d_val.as_ptr() as *mut c_char, 0),
            sys::OSSL_PARAM_construct_end(),
        ];
        if sys::EVP_MAC_CTX_set_params(mac_ctx, params.as_ptr()) == 1 {
            1
        } else {
            -1
        }
    }
}

extern "C" fn gen_cb(ssl_ptr: *mut sys::SSL, _arg: *mut c_void) -> c_int {
    let result = catch_unwind(AssertUnwindSafe(|| gen_cb_impl(ssl_ptr)));
    match result {
        Ok(v) => v,
        Err(_) => 0,
    }
}

fn gen_cb_impl(ssl_ptr: *mut sys::SSL) -> c_int {
    if ssl_ptr.is_null() {
        return 0;
    }
    let ssl = unsafe { SslRef::from_ptr(ssl_ptr) };
    let ctx = ssl.ssl_context();
    let index = match get_index() {
        Ok(i) => i,
        Err(_) => return 0,
    };
    let state = match ctx.ex_data(index) {
        Some(s) => s,
        None => return 0,
    };

    state.issue_ok.store(false, Ordering::Release);
    let group = crate::negotiated_group(ssl);
    let group = if group == 0 {
        state.resumed_group.load(Ordering::SeqCst)
    } else {
        group
    };

    if group == 0 {
        return 1;
    }

    let plain = group.to_be_bytes();
    if let Some(sealed) = state.provider.seal(&plain) {
        if sealed.len() <= MAX_SEALED_SIZE {
            let session_ptr = unsafe { sys::SSL_get_session(ssl_ptr) };
            if !session_ptr.is_null() {
                if unsafe {
                    SSL_SESSION_set1_ticket_appdata(
                        session_ptr,
                        sealed.as_ptr() as *const c_void,
                        sealed.len(),
                    )
                } == 1
                {
                    state.issue_ok.store(true, Ordering::SeqCst);
                    return 1;
                }
            }
        }
    }
    state.issue_ok.store(false, Ordering::SeqCst);
    1
}

extern "C" fn dec_cb(
    ssl_ptr: *mut sys::SSL,
    session_ptr: *mut sys::SSL_SESSION,
    _keyname: *const c_uchar,
    _keyname_len: usize,
    status: c_int,
    _arg: *mut c_void,
) -> c_int {
    let result = catch_unwind(AssertUnwindSafe(|| {
        dec_cb_impl(ssl_ptr, session_ptr, status)
    }));
    match result {
        Ok(v) => v,
        Err(_) => 2,
    }
}

fn dec_cb_impl(
    _ssl_ptr: *mut sys::SSL,
    session_ptr: *mut sys::SSL_SESSION,
    status: c_int,
) -> c_int {
    if _ssl_ptr.is_null() || session_ptr.is_null() {
        return 2;
    }

    if status != 5 && status != 6 {
        return 2;
    }

    let mut data_ptr: *mut c_void = std::ptr::null_mut();
    let mut len: usize = 0;
    if unsafe { SSL_SESSION_get0_ticket_appdata(session_ptr, &mut data_ptr, &mut len) } != 1 {
        return 2;
    }
    if data_ptr.is_null() || len == 0 || len > MAX_SEALED_SIZE {
        return 2;
    }

    let sealed = unsafe { std::slice::from_raw_parts(data_ptr as *const u8, len) };
    let ctx = unsafe { SslRef::from_ptr(_ssl_ptr).ssl_context() };
    let index = match get_index() {
        Ok(i) => i,
        Err(_) => return 2,
    };
    let state = match ctx.ex_data(index) {
        Some(s) => s,
        None => return 2,
    };

    if let Some(plain) = state.provider.open(sealed) {
        if plain.len() == PAYLOAD_LEN {
            let bytes: [u8; PAYLOAD_LEN] = plain.try_into().unwrap();
            let group = i64::from_be_bytes(bytes);
            if group != 0 {
                state.resumed_group.store(group, Ordering::SeqCst);
                return if status == 6 { 4 } else { 3 };
            }
        }
    }
    2
}

impl ServerTickets {
    pub fn new(provider: Arc<dyn ServerTicketProvider>) -> Self {
        Self {
            inner: Arc::new(State {
                provider,
                resumed_group: AtomicI64::new(0),
                issue_ok: AtomicBool::new(false),
            }),
        }
    }

    pub fn resumed_group(&self) -> Option<i64> {
        let g = self.inner.resumed_group.load(Ordering::SeqCst);
        if g == 0 { None } else { Some(g) }
    }

    pub fn configure(
        &self,
        ctx: &mut SslContextBuilder,
        binding: &[u8; 32],
    ) -> std::io::Result<()> {
        let index = get_index().map_err(std::io::Error::other)?;
        ctx.clear_options(SslOptions::NO_TICKET);
        ctx.set_session_cache_mode(SslSessionCacheMode::SERVER | SslSessionCacheMode::NO_INTERNAL);
        ctx.set_session_id_context(binding)
            .map_err(std::io::Error::other)?;
        ctx.set_ex_data(index, self.inner.clone());
        unsafe {
            SSL_CTX_set_timeout(ctx.as_ptr(), 604800);
            if SSL_CTX_set_tlsext_ticket_key_evp_cb(ctx.as_ptr(), key_cb) != 1
                || SSL_CTX_set_session_ticket_cb(ctx.as_ptr(), gen_cb, dec_cb, std::ptr::null_mut())
                    != 1
            {
                return Err(std::io::Error::other(ErrorStack::get()));
            }
        }
        Ok(())
    }
}
unsafe extern "C" {
    fn SSL_CTX_set_timeout(ctx: *mut sys::SSL_CTX, time: std::ffi::c_long) -> std::ffi::c_long;
}
