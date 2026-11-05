//! SignedData through this provider, crossed with software in both directions: messages an
//! [`OpenSslSigningKey`] signs are verified by a PkiEnvironment holding only certval's software
//! verifiers, and messages certval-cms's software signs are verified, and hashed, by a
//! PkiEnvironment holding only this provider.
//!
//! RSA PKCS #1 v1.5 and RSASSA-PSS with each digest, ECDSA on P-256, P-384 and P-521, and, on
//! OpenSSL 3.5 or later with the `pqc` feature, which gives software an ML-DSA verifier, pure ML-DSA.

#![cfg(feature = "cms")]

use std::sync::Arc;

use certval::PkiEnvironment;
use certval_cms::{
    rsa_pss, CmsEnvironment, DigestAlgorithm, SignedDataBuilder, Signer, SignerPolicy,
    SigningCredential, SoftwareSigningKey,
};
use certval_openssl::{OpenSslCrypto, OpenSslSigningKey};
use der::Decode;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{extension::SubjectKeyIdentifier, X509Builder, X509NameBuilder};
use x509_cert::Certificate;

const MESSAGE: &[u8] = b"certval-openssl signed content";

const DIGESTS: [DigestAlgorithm; 3] = [
    DigestAlgorithm::Sha256,
    DigestAlgorithm::Sha384,
    DigestAlgorithm::Sha512,
];

/// A CmsEnvironment over a PkiEnvironment holding only certval's software.
fn software() -> CmsEnvironment {
    let mut pe = PkiEnvironment::default();
    pe.populate_5280_pki_environment();
    let mut env = CmsEnvironment::new();
    env.set_pki_environment(Arc::new(pe));
    env
}

/// A CmsEnvironment over a PkiEnvironment holding only this provider, for hashing and verifying.
fn openssl_only() -> CmsEnvironment {
    let mut pe = PkiEnvironment::default();
    pe.add_calculate_hash_callback(OpenSslCrypto::new());
    pe.add_verify_signature_message_callback(OpenSslCrypto::new());
    pe.add_verify_signature_digest_callback(OpenSslCrypto::new());
    let mut env = CmsEnvironment::new();
    env.set_pki_environment(Arc::new(pe));
    env
}

/// A certificate for `key` with a subject key identifier, issued by a throwaway P-256 CA. No
/// signer is vetted here, so the CA need not be trusted.
fn certificate(key: &PKey<Private>) -> Certificate {
    let ca = PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "certval-openssl signer")
        .unwrap();
    let name = name.build();
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    let skid = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(skid).unwrap();
    builder.sign(&ca, MessageDigest::sha256()).unwrap();
    Certificate::from_der(&builder.build().to_der().unwrap()).unwrap()
}

/// Runs `test` on a thread with an 8 MiB stack. With certval's `pqc` feature, software signature
/// verification in a debug build exceeds the 2 MiB a test thread has by default, even when the
/// algorithm verified is not a post-quantum one.
fn with_large_stack(test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(test)
        .unwrap()
        .join()
        .unwrap();
}

/// The two credentials for one key.
fn credentials(key: PKey<Private>) -> (OpenSslSigningKey, SoftwareSigningKey) {
    let cert = certificate(&key);
    let software =
        SoftwareSigningKey::from_pkcs8_der(cert.clone(), &key.private_key_to_pkcs8().unwrap())
            .unwrap();
    (OpenSslSigningKey::new(cert, key).unwrap(), software)
}

/// Signs with `credential` through `signing`, and verifies through `verifying`.
fn assert_crosses(
    signing: &CmsEnvironment,
    verifying: &CmsEnvironment,
    signer: Signer<'_>,
    name: &str,
) {
    let ci = SignedDataBuilder::new(MESSAGE)
        .add_signer(signer)
        .build(signing)
        .unwrap_or_else(|e| panic!("{name}: signing: {e}"))
        .content_info;
    let verified = verifying
        .verify_signed_data(&ci, None, None, SignerPolicy::All)
        .unwrap_or_else(|e| panic!("{name}: verifying: {e}"));
    assert_eq!(verified.content, MESSAGE, "{name}");
}

/// Both crossings for one credential pair and signer settings.
fn cross_both_ways(
    openssl: &OpenSslSigningKey,
    software: &SoftwareSigningKey,
    configure: impl Fn(Signer<'_>) -> Signer<'_>,
    name: &str,
) {
    let (software_env, openssl_env) = (self::software(), openssl_only());
    assert_crosses(
        &software_env,
        &software_env,
        configure(Signer::explicit(openssl as &dyn SigningCredential)),
        &format!("OpenSSL signs, software verifies: {name}"),
    );
    assert_crosses(
        &openssl_env,
        &openssl_env,
        configure(Signer::explicit(software as &dyn SigningCredential)),
        &format!("software signs, OpenSSL verifies: {name}"),
    );
}

#[test]
fn rsa_pkcs1v15_and_pss_with_each_digest() {
    with_large_stack(rsa_pkcs1v15_and_pss);
}

fn rsa_pkcs1v15_and_pss() {
    let (openssl, software) = credentials(PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap());
    for digest in DIGESTS {
        cross_both_ways(
            &openssl,
            &software,
            |s| s.digest(digest),
            &format!("PKCS #1 v1.5 {digest:?}"),
        );
        cross_both_ways(
            &openssl,
            &software,
            |s| {
                s.digest(digest)
                    .signature_algorithm(rsa_pss(digest).unwrap())
            },
            &format!("PSS {digest:?}"),
        );
    }
}

#[test]
fn ecdsa_on_each_curve_with_each_digest() {
    with_large_stack(ecdsa_on_each_curve);
}

fn ecdsa_on_each_curve() {
    for curve in [Nid::X9_62_PRIME256V1, Nid::SECP384R1, Nid::SECP521R1] {
        let key =
            PKey::from_ec_key(EcKey::generate(&EcGroup::from_curve_name(curve).unwrap()).unwrap())
                .unwrap();
        let (openssl, software) = credentials(key);
        for digest in DIGESTS {
            cross_both_ways(
                &openssl,
                &software,
                |s| s.digest(digest),
                &format!("{curve:?} {digest:?}"),
            );
        }
    }
}

/// Generates a key for `name` ("ML-DSA-65", etc.). The `openssl` crate generates keys only for the
/// algorithms it names, which ML-DSA is not.
#[cfg(feature = "pqc")]
fn generate(name: &std::ffi::CStr) -> PKey<Private> {
    use foreign_types::ForeignType;
    // SAFETY: the context is freed before return, and the key it generates is handed to a PKey,
    // which frees it.
    unsafe {
        let ctx = openssl_sys::EVP_PKEY_CTX_new_from_name(
            std::ptr::null_mut(),
            name.as_ptr(),
            std::ptr::null(),
        );
        assert!(!ctx.is_null(), "no {name:?} in this OpenSSL");
        assert_eq!(openssl_sys::EVP_PKEY_keygen_init(ctx), 1);
        let mut key = std::ptr::null_mut();
        assert_eq!(openssl_sys::EVP_PKEY_generate(ctx, &mut key), 1);
        openssl_sys::EVP_PKEY_CTX_free(ctx);
        PKey::from_ptr(key)
    }
}

#[cfg(feature = "pqc")]
#[test]
fn ml_dsa_with_each_parameter_set() {
    with_large_stack(ml_dsa);
}

#[cfg(feature = "pqc")]
fn ml_dsa() {
    if openssl::version::number() < 0x3050_0000 {
        eprintln!(
            "skipped: {} is older than OpenSSL 3.5, the first with ML-DSA",
            openssl::version::version()
        );
        return;
    }
    for name in [c"ML-DSA-44", c"ML-DSA-65", c"ML-DSA-87"] {
        let (openssl, software) = credentials(generate(name));
        cross_both_ways(&openssl, &software, |s| s, &format!("{name:?}"));
    }
}
