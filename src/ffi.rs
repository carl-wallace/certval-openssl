//! The two calls the `openssl` crate does not wrap in the form this provider needs.

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
