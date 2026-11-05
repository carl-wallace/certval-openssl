//! The calls the `openssl` crate does not wrap in the form this provider needs.

/// Returns whether the default library context's default properties require `fips=yes`, which is
/// what routes every algorithm fetch through the FIPS provider.
pub(crate) fn default_properties_require_fips() -> bool {
    openssl_sys::init();
    // SAFETY: a null library context names the default one, and the call only reads its
    // properties.
    unsafe { openssl_sys::EVP_default_properties_is_fips_enabled(std::ptr::null_mut()) == 1 }
}

/// Verifies `signature` over `digest` with a context already initialized for verification.
///
/// OpenSSL documents `EVP_PKEY_verify` as returning 1 for a valid signature, 0 for one that did
/// not verify and nothing more, and a negative value for any other error. `PkeyCtx::verify`
/// reports a 0 as an error whenever OpenSSL left anything on its error queue, which it does for an
/// invalid ECDSA signature, so a bad signature would be indistinguishable from a refusal. This
/// keeps OpenSSL's distinction: `Ok(false)` for a 0, `Err` only for a negative result.
pub(crate) fn pkey_verify(
    ctx: &mut openssl::pkey_ctx::PkeyCtxRef<openssl::pkey::Public>,
    digest: &[u8],
    signature: &[u8],
) -> Result<bool, openssl::error::ErrorStack> {
    use foreign_types::ForeignTypeRef;
    // SAFETY: the context is live for the borrow, and both buffers are live with the lengths
    // passed.
    let result = unsafe {
        openssl_sys::EVP_PKEY_verify(
            ctx.as_ptr(),
            signature.as_ptr(),
            signature.len(),
            digest.as_ptr(),
            digest.len(),
        )
    };
    match result {
        1 => Ok(true),
        0 => {
            // The queue explains the failure, which is already the verdict; it is drained so
            // nothing is left for a later call to misreport.
            let _ = openssl::error::ErrorStack::get();
            Ok(false)
        }
        _ => Err(openssl::error::ErrorStack::get()),
    }
}

/// Sets an ECDH derivation context to run its shared secret through the ANSI X9.63 KDF with
/// `digest` (an OpenSSL digest name, e.g. "SHA256") and `shared_info`, producing `out_len` octets.
///
/// OpenSSL's own CMS sets up key agreement this way, so the shared secret never leaves OpenSSL:
/// the derivation returns the key-encryption key. The `openssl` crate does not wrap these
/// parameters, so they are set with `EVP_PKEY_CTX_set_params`.
#[cfg(feature = "cms")]
pub(crate) fn set_ecdh_x963_kdf(
    ctx: &mut openssl::pkey_ctx::PkeyCtxRef<openssl::pkey::Private>,
    digest: &std::ffi::CStr,
    out_len: usize,
    shared_info: &[u8],
) -> Result<(), openssl::error::ErrorStack> {
    use foreign_types::ForeignTypeRef;
    use std::ffi::c_char;

    extern "C" {
        fn OSSL_PARAM_construct_utf8_string(
            key: *const c_char,
            buf: *mut c_char,
            bsize: usize,
        ) -> openssl_sys::OSSL_PARAM;
        fn OSSL_PARAM_construct_size_t(
            key: *const c_char,
            buf: *mut usize,
        ) -> openssl_sys::OSSL_PARAM;
    }

    let mut out_len = out_len;
    // SAFETY: OpenSSL reads the parameters, and does not keep them, during the
    // EVP_PKEY_CTX_set_params call, while every buffer they point to is live. The string and octet
    // buffers are only read, though the constructors' signatures take mutable pointers.
    let result = unsafe {
        let params = [
            OSSL_PARAM_construct_utf8_string(
                c"kdf-type".as_ptr(),
                c"X963KDF".as_ptr() as *mut c_char,
                0,
            ),
            OSSL_PARAM_construct_utf8_string(
                c"kdf-digest".as_ptr(),
                digest.as_ptr() as *mut c_char,
                0,
            ),
            OSSL_PARAM_construct_size_t(c"kdf-outlen".as_ptr(), &mut out_len),
            openssl_sys::OSSL_PARAM_construct_octet_string(
                c"kdf-ukm".as_ptr(),
                shared_info.as_ptr() as *mut std::ffi::c_void,
                shared_info.len(),
            ),
            openssl_sys::OSSL_PARAM_construct_end(),
        ];
        openssl_sys::EVP_PKEY_CTX_set_params(ctx.as_ptr(), params.as_ptr())
    };
    if result == 1 {
        Ok(())
    } else {
        Err(openssl::error::ErrorStack::get())
    }
}

/// Encapsulates to the public key a context was created for, returning the ciphertext and the
/// shared secret. The `openssl` crate does not wrap `EVP_PKEY_encapsulate`.
#[cfg(feature = "cms")]
pub(crate) fn encapsulate(
    ctx: &mut openssl::pkey_ctx::PkeyCtxRef<openssl::pkey::Public>,
) -> Result<(Vec<u8>, zeroize::Zeroizing<Vec<u8>>), openssl::error::ErrorStack> {
    use foreign_types::ForeignTypeRef;

    let check = |result: std::ffi::c_int| {
        if result == 1 {
            Ok(())
        } else {
            Err(openssl::error::ErrorStack::get())
        }
    };
    let (mut ct_len, mut ss_len) = (0usize, 0usize);
    // SAFETY: the context is live for the borrow. The first EVP_PKEY_encapsulate call passes null
    // output buffers, so OpenSSL only reports the lengths; the second passes buffers of those
    // lengths, and OpenSSL writes at most that much and reports what it wrote.
    unsafe {
        check(openssl_sys::EVP_PKEY_encapsulate_init(
            ctx.as_ptr(),
            std::ptr::null(),
        ))?;
        check(openssl_sys::EVP_PKEY_encapsulate(
            ctx.as_ptr(),
            std::ptr::null_mut(),
            &mut ct_len,
            std::ptr::null_mut(),
            &mut ss_len,
        ))?;
        let mut ct = vec![0u8; ct_len];
        let mut ss = zeroize::Zeroizing::new(vec![0u8; ss_len]);
        check(openssl_sys::EVP_PKEY_encapsulate(
            ctx.as_ptr(),
            ct.as_mut_ptr(),
            &mut ct_len,
            ss.as_mut_ptr(),
            &mut ss_len,
        ))?;
        ct.truncate(ct_len);
        ss.truncate(ss_len);
        Ok((ct, ss))
    }
}

/// Decapsulates `ciphertext` with the private key a context was created for, returning the shared
/// secret. The `openssl` crate does not wrap `EVP_PKEY_decapsulate`.
#[cfg(feature = "cms")]
pub(crate) fn decapsulate(
    ctx: &mut openssl::pkey_ctx::PkeyCtxRef<openssl::pkey::Private>,
    ciphertext: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>, openssl::error::ErrorStack> {
    use foreign_types::ForeignTypeRef;

    let check = |result: std::ffi::c_int| {
        if result == 1 {
            Ok(())
        } else {
            Err(openssl::error::ErrorStack::get())
        }
    };
    let mut ss_len = 0usize;
    // SAFETY: the context is live for the borrow, and `ciphertext` is live with the length passed.
    // The first EVP_PKEY_decapsulate call passes a null output buffer, so OpenSSL only reports the
    // length; the second passes a buffer of that length, and OpenSSL writes at most that much and
    // reports what it wrote.
    unsafe {
        check(openssl_sys::EVP_PKEY_decapsulate_init(
            ctx.as_ptr(),
            std::ptr::null(),
        ))?;
        check(openssl_sys::EVP_PKEY_decapsulate(
            ctx.as_ptr(),
            std::ptr::null_mut(),
            &mut ss_len,
            ciphertext.as_ptr(),
            ciphertext.len(),
        ))?;
        let mut ss = zeroize::Zeroizing::new(vec![0u8; ss_len]);
        check(openssl_sys::EVP_PKEY_decapsulate(
            ctx.as_ptr(),
            ss.as_mut_ptr(),
            &mut ss_len,
            ciphertext.as_ptr(),
            ciphertext.len(),
        ))?;
        ss.truncate(ss_len);
        Ok(ss)
    }
}
