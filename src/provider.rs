//! The provider that implements certval's hashing and verification interfaces against OpenSSL.

use crate::algorithm::{is_pure_pqc, signature_scheme, Hash, Padding, Scheme};
use certval::{
    CalculateHash, PathValidationStatus, PkiEnvironment, VerifySignatureDigest,
    VerifySignatureMessage,
};
use der::asn1::BitString;
use der::Encode;
use log::debug;
use openssl::error::ErrorStack;
use openssl::md::{Md, MdRef};
use openssl::pkey::{Id, PKey, Public};
use openssl::pkey_ctx::PkeyCtx;
use openssl::rsa::Padding as RsaPadding;
use openssl::sign::{RsaPssSaltlen, Verifier};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

/// A [`certval`] crypto provider backed by the system's OpenSSL 3.
///
/// The value holds no state: each verification decodes the issuer's key, verifies, and frees the
/// key. Decoding a public key is an in-process call with no session behind it, so there is no
/// round trip for a cache to save. The same value can be registered in every role:
///
/// ```no_run
/// # use certval::PkiEnvironment;
/// # use certval_openssl::OpenSslCrypto;
/// # let mut pe = PkiEnvironment::default();
/// pe.add_calculate_hash_callback(OpenSslCrypto::new());
/// pe.add_verify_signature_message_callback(OpenSslCrypto::new());
/// pe.add_verify_signature_digest_callback(OpenSslCrypto::new());
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenSslCrypto {
    _private: (),
}

fn md(hash: Hash) -> &'static MdRef {
    match hash {
        Hash::Sha1 => Md::sha1(),
        Hash::Sha224 => Md::sha224(),
        Hash::Sha256 => Md::sha256(),
        Hash::Sha384 => Md::sha384(),
        Hash::Sha512 => Md::sha512(),
    }
}

/// Decodes `spki` and checks that the key can carry a signature with `padding`.
///
/// OpenSSL decodes the whole `SubjectPublicKeyInfo`, curve included, so no curve check is needed
/// here. What is checked is the pairing of key and signature: a PKCS #1 v1.5 signature needs a key
/// identified as `rsaEncryption`, because RFC 4055 restricts a key identified as `id-RSASSA-PSS`
/// to PSS and certval's software verifier rejects the combination, so it is declined here and
/// software gives that verdict.
fn public_key(spki: &SubjectPublicKeyInfoOwned, padding: Padding) -> Option<PKey<Public>> {
    let encoded = spki.to_der().ok()?;
    let key = match PKey::public_key_from_der(&encoded) {
        Ok(key) => key,
        Err(e) => {
            debug!("OpenSSL declined a public key: {e}");
            return None;
        }
    };
    let acceptable = match padding {
        Padding::Pkcs1 => key.id() == Id::RSA,
        Padding::Pss { .. } => key.id() == Id::RSA || key.id() == Id::RSA_PSS,
        Padding::Ecdsa => key.id() == Id::EC,
    };
    acceptable.then_some(key)
}

/// The padding settings both verification paths apply, expressed once.
trait RsaSettings {
    fn padding(&mut self, padding: RsaPadding) -> Result<(), ErrorStack>;
    fn pss_salt_len(&mut self, len: RsaPssSaltlen) -> Result<(), ErrorStack>;
    fn mgf1(&mut self, hash: Hash) -> Result<(), ErrorStack>;
}

impl RsaSettings for Verifier<'_> {
    fn padding(&mut self, padding: RsaPadding) -> Result<(), ErrorStack> {
        self.set_rsa_padding(padding)
    }
    fn pss_salt_len(&mut self, len: RsaPssSaltlen) -> Result<(), ErrorStack> {
        self.set_rsa_pss_saltlen(len)
    }
    fn mgf1(&mut self, hash: Hash) -> Result<(), ErrorStack> {
        self.set_rsa_mgf1_md(hash.digest())
    }
}

impl RsaSettings for PkeyCtx<Public> {
    fn padding(&mut self, padding: RsaPadding) -> Result<(), ErrorStack> {
        self.set_rsa_padding(padding)
    }
    fn pss_salt_len(&mut self, len: RsaPssSaltlen) -> Result<(), ErrorStack> {
        self.set_rsa_pss_saltlen(len)
    }
    fn mgf1(&mut self, hash: Hash) -> Result<(), ErrorStack> {
        self.set_rsa_mgf1_md(md(hash))
    }
}

/// Applies the padding a scheme calls for. ECDSA needs none.
fn apply_padding(target: &mut impl RsaSettings, padding: Padding) -> Result<(), ErrorStack> {
    match padding {
        Padding::Pkcs1 => target.padding(RsaPadding::PKCS1),
        Padding::Pss { mgf_hash, salt_len } => {
            target.padding(RsaPadding::PKCS1_PSS)?;
            target.mgf1(mgf_hash)?;
            let salt_len = i32::try_from(salt_len).map_err(|_| ErrorStack::get())?;
            target.pss_salt_len(RsaPssSaltlen::custom(salt_len))
        }
        Padding::Ecdsa => Ok(()),
    }
}

/// Turns OpenSSL's answer into the terms certval's interfaces are defined in.
fn outcome(result: Result<bool, ErrorStack>) -> certval::Result<()> {
    match result {
        // OpenSSL verified the signature.
        Ok(true) => Ok(()),

        // OpenSSL reached a verdict and it was negative. The environment treats this as final and
        // consults no other implementation.
        Ok(false) => Err(certval::Error::PathValidation(
            PathValidationStatus::SignatureVerificationFailure,
        )),

        // An error is OpenSSL declining the request (an algorithm the configured providers do not
        // offer, or parameters they refuse) rather than judging the signature, so another
        // implementation answers.
        Err(e) => {
            debug!("OpenSSL could not verify a signature: {e}");
            Err(certval::Error::Unrecognized)
        }
    }
}

impl OpenSslCrypto {
    /// Returns a provider.
    pub fn new() -> Self {
        OpenSslCrypto { _private: () }
    }

    /// Reports whether OpenSSL's default library context requires `fips=yes` of every algorithm
    /// it fetches, which is what routes the provider's hashing and verification through the FIPS
    /// provider.
    ///
    /// The provider behaves the same either way; this is for a caller whose deployment requires
    /// FIPS and wants to confirm the system is configured for it before relying on the provider.
    pub fn fips_mode_enabled() -> bool {
        crate::ffi::default_properties_require_fips()
    }

    /// Returns OpenSSL's version string, for reporting which library answered.
    pub fn openssl_version() -> &'static str {
        openssl::version::version()
    }

    fn verify_message(
        &self,
        spki: &SubjectPublicKeyInfoOwned,
        scheme: Scheme,
        message: &[u8],
        signature: &[u8],
    ) -> certval::Result<()> {
        let Some(key) = public_key(spki, scheme.padding) else {
            return Err(certval::Error::Unrecognized);
        };
        let result = Verifier::new(scheme.hash.digest(), &key).and_then(|mut verifier| {
            apply_padding(&mut verifier, scheme.padding)?;
            verifier.verify_oneshot(signature, message)
        });
        outcome(result)
    }

    /// Verifies a pure ML-DSA or SLH-DSA signature over `message`.
    ///
    /// The key must be identified by the same object identifier as the signature, which RFC 9881
    /// and RFC 9909 require, and carry no parameters. OpenSSL decodes it by that identifier, so an
    /// OpenSSL older than 3.5, which has neither algorithm, fails to decode it and the provider
    /// declines. The signature carries no context string, which is what a certificate signature
    /// uses and what OpenSSL defaults to.
    fn verify_pure(
        &self,
        spki: &SubjectPublicKeyInfoOwned,
        signature_alg: &AlgorithmIdentifierOwned,
        message: &[u8],
        signature: &[u8],
    ) -> certval::Result<()> {
        if spki.algorithm.oid != signature_alg.oid || spki.algorithm.parameters.is_some() {
            return Err(certval::Error::Unrecognized);
        }
        let Ok(encoded) = spki.to_der() else {
            return Err(certval::Error::Unrecognized);
        };
        let key = match PKey::public_key_from_der(&encoded) {
            Ok(key) => key,
            Err(e) => {
                debug!("OpenSSL declined a {} public key: {e}", signature_alg.oid);
                return Err(certval::Error::Unrecognized);
            }
        };
        let result = Verifier::new_without_digest(&key)
            .and_then(|mut verifier| verifier.verify_oneshot(signature, message));
        outcome(result)
    }

    fn verify_digest(
        &self,
        spki: &SubjectPublicKeyInfoOwned,
        scheme: Scheme,
        digest: &[u8],
        signature: &[u8],
    ) -> certval::Result<()> {
        if digest.len() != scheme.hash.len() {
            return Err(certval::Error::Unrecognized);
        }
        let Some(key) = public_key(spki, scheme.padding) else {
            return Err(certval::Error::Unrecognized);
        };
        let ctx = PkeyCtx::new(&key).and_then(|mut ctx| {
            ctx.verify_init()?;
            ctx.set_signature_md(md(scheme.hash))?;
            apply_padding(&mut ctx, scheme.padding)?;
            Ok(ctx)
        });
        let result = ctx.and_then(|mut ctx| crate::ffi::pkey_verify(&mut ctx, digest, signature));
        outcome(result)
    }
}

impl CalculateHash for OpenSslCrypto {
    fn calculate_hash(
        &self,
        _pe: &PkiEnvironment,
        hash_alg: &AlgorithmIdentifierOwned,
        buffer_to_hash: &[u8],
    ) -> certval::Result<Vec<u8>> {
        let Some(hash) = Hash::from_oid(&hash_alg.oid) else {
            return Err(certval::Error::Unrecognized);
        };
        match openssl::hash::hash(hash.digest(), buffer_to_hash) {
            Ok(digest) => Ok(digest.to_vec()),
            Err(e) => {
                debug!("OpenSSL could not calculate a digest: {e}");
                Err(certval::Error::Unrecognized)
            }
        }
    }
}

impl VerifySignatureMessage for OpenSslCrypto {
    fn verify_signature_message(
        &self,
        _pe: &PkiEnvironment,
        message_to_verify: &[u8],
        signature: &BitString,
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
    ) -> certval::Result<()> {
        let signature_bytes = signature.as_bytes().ok_or(certval::Error::ParseError)?;
        if is_pure_pqc(signature_alg) {
            return self.verify_pure(spki, signature_alg, message_to_verify, signature_bytes);
        }
        let Some(scheme) = signature_scheme(signature_alg) else {
            return Err(certval::Error::Unrecognized);
        };
        self.verify_message(spki, scheme, message_to_verify, signature_bytes)
    }
}

impl VerifySignatureDigest for OpenSslCrypto {
    fn verify_signature_digest(
        &self,
        _pe: &PkiEnvironment,
        hash_to_verify: &[u8],
        signature: &BitString,
        signature_alg: &AlgorithmIdentifierOwned,
        spki: &SubjectPublicKeyInfoOwned,
    ) -> certval::Result<()> {
        let Some(scheme) = signature_scheme(signature_alg) else {
            return Err(certval::Error::Unrecognized);
        };
        let signature = signature.as_bytes().ok_or(certval::Error::ParseError)?;
        self.verify_digest(spki, scheme, hash_to_verify, signature)
    }
}
