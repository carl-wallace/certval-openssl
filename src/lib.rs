//! OpenSSL crypto provider for [`certval`].
//!
//! [`certval`] performs hashing and signature verification through callbacks registered on a
//! [`PkiEnvironment`](certval::PkiEnvironment). This crate supplies implementations of those
//! callbacks that route the work to the system's OpenSSL 3, so certification path validation can be
//! performed with OpenSSL's FIPS provider, where the system has one configured, rather than the
//! in-process software implementation.
//!
//! ```no_run
//! use certval::PkiEnvironment;
//! use certval_openssl::OpenSslCrypto;
//!
//! let mut pe = PkiEnvironment::default();
//!
//! // Registering before populate_5280_pki_environment puts OpenSSL ahead of the software
//! // implementations, so it is consulted first and software answers only what it declined.
//! pe.add_calculate_hash_callback(OpenSslCrypto::new());
//! pe.add_verify_signature_message_callback(OpenSslCrypto::new());
//! pe.add_verify_signature_digest_callback(OpenSslCrypto::new());
//!
//! pe.populate_5280_pki_environment();
//! ```
//!
//! # Registration is additive
//!
//! [`PkiEnvironment`](certval::PkiEnvironment) consults registered implementations in order and
//! stops at the first verdict. The provider reports a rejection only when OpenSSL judged the
//! signature invalid; anything else it declines, and a declined verification falls through to the
//! next implementation. A caller who requires that every verification reach OpenSSL must make the
//! registration exclusive by clearing the software callbacks first:
//!
//! ```no_run
//! # use certval::PkiEnvironment;
//! # use certval_openssl::OpenSslCrypto;
//! # let mut pe = PkiEnvironment::default();
//! pe.populate_5280_pki_environment();
//! pe.clear_verify_signature_message_callbacks();
//! pe.clear_verify_signature_digest_callbacks();
//! pe.add_verify_signature_message_callback(OpenSslCrypto::new());
//! pe.add_verify_signature_digest_callback(OpenSslCrypto::new());
//! ```
//!
//! # FIPS
//!
//! The provider uses OpenSSL's default library context, so which implementation answers is decided
//! by the system's OpenSSL configuration, not by this crate. A system configured for FIPS (an
//! `openssl.cnf` that activates the `fips` provider and sets `default_properties = fips=yes`, as a
//! distribution's FIPS mode does) routes every hash and verification here through the FIPS
//! provider. [`OpenSslCrypto::fips_mode_enabled`] reports whether that is the case.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod algorithm;
#[allow(unsafe_code)]
mod ffi;
mod provider;

pub use provider::OpenSslCrypto;
