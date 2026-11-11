//! Messages built with only this provider registered on a certval-cms environment, so every
//! operation reaches OpenSSL, then decrypted by OpenSSL's CMS implementation, which reads each
//! message's encoding independently of how the provider was wired: RSA key transport with each
//! algorithm, ECDH on P-256, P-384 and P-521 with each KDF hash and wrap, and ML-KEM with each
//! parameter set, KDF and wrap, with and without user keying material, plus every content
//! encryption algorithm.
//!
//! ML-KEM needs OpenSSL 3.5, and OpenSSL's CMS reads KEMRecipientInfo from 3.6 and
//! AuthEnvelopedData's authenticated attributes as RFC 5083 tags them from 3.6.4; against an older
//! OpenSSL those checks are skipped, and say so.

#![cfg(feature = "cms")]

use certval_cms::{
    AuthEnvelopedDataBuilder, CmsEnvironment, ContentEncryptionAlgorithm, EnvelopedDataBuilder,
    Error, KdfAlgorithm, KemRecipient, KeyAgreeRecipient, KeyAgreementAlgorithm, KeyTransRecipient,
    KeyTransportAlgorithm, KeyWrapAlgorithm, RecipientInfoBuilder,
};
use certval_openssl::OpenSslCrypto;
use cms::{
    cert::x509::attr::Attribute, content_info::ContentInfo, enveloped_data::RecipientIdentifier,
};
use const_oid::db::rfc5911::{ID_CONTENT_TYPE, ID_DATA};
use der::{
    asn1::{OctetString, SetOfVec},
    Any, Decode, Encode,
};
use getrandom::SysRng;
use openssl::cms::CmsContentInfo;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use rand_core::UnwrapErr;
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::ext::pkix::SubjectKeyIdentifier;

type Rng = UnwrapErr<SysRng>;

const MESSAGE: &[u8] =
    b"certval-openssl recipients, longer than one AES block so that padding is used";

const CONTENT: [ContentEncryptionAlgorithm; 6] = [
    ContentEncryptionAlgorithm::Aes128Cbc,
    ContentEncryptionAlgorithm::Aes192Cbc,
    ContentEncryptionAlgorithm::Aes256Cbc,
    ContentEncryptionAlgorithm::Aes128Gcm,
    ContentEncryptionAlgorithm::Aes192Gcm,
    ContentEncryptionAlgorithm::Aes256Gcm,
];

const WRAPS: [KeyWrapAlgorithm; 3] = [
    KeyWrapAlgorithm::Aes128,
    KeyWrapAlgorithm::Aes192,
    KeyWrapAlgorithm::Aes256,
];

/// OpenSSL 3.5.0, the first with ML-KEM, in OpenSSL's version number layout.
const OPENSSL_3_5: i64 = 0x3050_0000;
/// OpenSSL 3.6.0, the first whose CMS reads KEMRecipientInfo.
const OPENSSL_3_6: i64 = 0x3060_0000;
/// OpenSSL 3.6.4, the first to read AuthEnvelopedData's authAttrs as RFC 5083 tags them.
const OPENSSL_3_6_4: i64 = 0x3060_0040;

/// An environment with only this provider registered, so nothing falls through to software.
fn openssl_only() -> CmsEnvironment {
    let mut env = CmsEnvironment::new();
    env.add_encrypt_content_callback(OpenSslCrypto::new());
    env.add_encrypt_key_transport_callback(OpenSslCrypto::new());
    env.add_encrypt_key_agreement_callback(OpenSslCrypto::new());
    env.add_encrypt_kem_callback(OpenSslCrypto::new());
    env
}

fn rng() -> Rng {
    UnwrapErr(SysRng)
}

fn rid() -> RecipientIdentifier {
    RecipientIdentifier::SubjectKeyIdentifier(SubjectKeyIdentifier(
        OctetString::new(vec![1, 2, 3, 4]).unwrap(),
    ))
}

fn spki(key: &PKey<Private>) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned::from_der(&key.public_key_to_der().unwrap()).unwrap()
}

fn content_type_attrs() -> SetOfVec<Attribute> {
    let mut values = SetOfVec::new();
    values.insert(Any::encode_from(&ID_DATA).unwrap()).unwrap();
    let mut attrs = SetOfVec::new();
    attrs
        .insert(Attribute {
            oid: ID_CONTENT_TYPE,
            values,
        })
        .unwrap();
    attrs
}

/// A message for one recipient with `alg`: EnvelopedData for CBC, AuthEnvelopedData for GCM, with
/// a content-type authenticated attribute when `auth_attrs`.
fn envelop<'e>(
    env: &'e CmsEnvironment,
    alg: ContentEncryptionAlgorithm,
    auth_attrs: bool,
    recipient: impl RecipientInfoBuilder<Rng = Rng> + 'e,
) -> Result<ContentInfo, Error> {
    if alg.is_authenticated() {
        let mut builder = AuthEnvelopedDataBuilder::new(MESSAGE, alg)?;
        if auth_attrs {
            builder.auth_attrs(content_type_attrs());
        }
        builder
            .add_recipient(recipient)
            .build_content_info(env, &mut rng())
    } else {
        EnvelopedDataBuilder::new(MESSAGE, alg)?
            .add_recipient(recipient)
            .build_content_info(env, &mut rng())
    }
}

/// Decrypts with OpenSSL's CMS, trying each recipient with `key`, and checks the content.
fn assert_decrypts(key: &PKey<Private>, ci: &ContentInfo, name: &str) {
    let cms = CmsContentInfo::from_der(&ci.to_der().unwrap())
        .unwrap_or_else(|e| panic!("{name}: OpenSSL could not decode the message: {e}"));
    let decrypted = cms
        .decrypt_without_cert_check(key)
        .unwrap_or_else(|e| panic!("{name}: OpenSSL could not decrypt the message: {e}"));
    assert_eq!(decrypted, MESSAGE, "{name}");
}

/// The content encryption algorithms and attribute choices this OpenSSL can decrypt.
fn contents() -> Vec<(ContentEncryptionAlgorithm, bool)> {
    let reads_auth_attrs = openssl::version::number() >= OPENSSL_3_6_4;
    if !reads_auth_attrs {
        eprintln!(
            "skipped for authenticated attributes: {} is older than OpenSSL 3.6.4",
            openssl::version::version()
        );
    }
    let mut contents = vec![];
    for alg in CONTENT {
        contents.push((alg, false));
        if alg.is_authenticated() && reads_auth_attrs {
            contents.push((alg, true));
        }
    }
    contents
}

/// Whether `built` is a FIPS provider declining RSAES-PKCS1-v1_5 encryption, a service FIPS does
/// not approve. OpenSSL 3.5's FIPS provider refuses it, while the 3.0 one performs it, so a
/// decline is accepted under FIPS rather than required; decryption is still expected.
fn fips_declines_pkcs1v15_encryption<T>(
    alg: KeyTransportAlgorithm,
    built: &Result<T, Error>,
) -> bool {
    alg == KeyTransportAlgorithm::RsaPkcs1v15
        && OpenSslCrypto::fips_mode_enabled()
        && matches!(built, Err(Error::Unrecognized))
}

#[test]
fn key_transport_with_each_algorithm_and_content_encryption() {
    let env = openssl_only();
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    for alg in [
        KeyTransportAlgorithm::RsaPkcs1v15,
        KeyTransportAlgorithm::RsaOaepSha1,
        KeyTransportAlgorithm::RsaOaepSha256,
        KeyTransportAlgorithm::RsaOaepSha384,
        KeyTransportAlgorithm::RsaOaepSha512,
    ] {
        for (content, auth_attrs) in contents() {
            let name = format!("{alg:?} {content:?} attrs={auth_attrs}");
            let recipient = KeyTransRecipient::new(&env, rid(), spki(&key), alg);
            let built = envelop(&env, content, auth_attrs, recipient);
            if fips_declines_pkcs1v15_encryption(alg, &built) {
                eprintln!("{name}: declined by the FIPS provider, which does not encrypt with it");
                continue;
            }
            let ci = built.unwrap_or_else(|e| panic!("{name}: building the message: {e:?}"));
            assert_decrypts(&key, &ci, &name);
        }
    }
}

fn key_agreement(curve: Nid) {
    let env = openssl_only();
    let group = EcGroup::from_curve_name(curve).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    for alg in [
        KeyAgreementAlgorithm::EcdhSha256,
        KeyAgreementAlgorithm::EcdhSha384,
        KeyAgreementAlgorithm::EcdhSha512,
        KeyAgreementAlgorithm::EcdhCofactorSha256,
        KeyAgreementAlgorithm::EcdhCofactorSha384,
        KeyAgreementAlgorithm::EcdhCofactorSha512,
    ] {
        for wrap in WRAPS {
            for ukm in [None, Some(b"user keying material".to_vec())] {
                let name = format!(
                    "{} {alg:?} {wrap:?} ukm={}",
                    curve.short_name().unwrap(),
                    ukm.is_some()
                );
                let recipient = KeyAgreeRecipient::new(&env, rid(), spki(&key), alg, wrap, ukm);
                let ci = envelop(
                    &env,
                    ContentEncryptionAlgorithm::Aes256Cbc,
                    false,
                    recipient,
                )
                .unwrap();
                assert_decrypts(&key, &ci, &name);
            }
        }
    }
}

#[test]
fn key_agreement_on_p256() {
    key_agreement(Nid::X9_62_PRIME256V1);
}

#[test]
fn key_agreement_on_p384() {
    key_agreement(Nid::SECP384R1);
}

#[test]
fn key_agreement_on_p521() {
    key_agreement(Nid::SECP521R1);
}

/// Generates a key for `name` ("ML-KEM-768", etc.). The `openssl` crate generates keys only for the
/// algorithms it names, which ML-KEM is not.
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

#[test]
fn kem_with_each_parameter_set_kdf_and_wrap() {
    let version = openssl::version::number();
    if version < OPENSSL_3_5 {
        eprintln!(
            "skipped: {} is older than OpenSSL 3.5, the first with ML-KEM",
            openssl::version::version()
        );
        return;
    }
    let decrypts = version >= OPENSSL_3_6;
    if !decrypts {
        eprintln!(
            "messages built but not decrypted: {} is older than OpenSSL 3.6, which added \
             KEMRecipientInfo",
            openssl::version::version()
        );
    }
    let env = openssl_only();
    for name in [c"ML-KEM-512", c"ML-KEM-768", c"ML-KEM-1024"] {
        let key = generate(name);
        for kdf in [
            KdfAlgorithm::HkdfSha256,
            KdfAlgorithm::HkdfSha384,
            KdfAlgorithm::HkdfSha512,
        ] {
            for wrap in WRAPS {
                for ukm in [None, Some(b"user keying material".to_vec())] {
                    let label = format!("{name:?} {kdf:?} {wrap:?} ukm={}", ukm.is_some());
                    let recipient = KemRecipient::new(&env, rid(), spki(&key), kdf, wrap, ukm);
                    let ci = envelop(
                        &env,
                        ContentEncryptionAlgorithm::Aes256Gcm,
                        false,
                        recipient,
                    )
                    .unwrap_or_else(|e| panic!("{label}: {e}"));
                    if decrypts {
                        assert_decrypts(&key, &ci, &label);
                    }
                }
            }
        }
    }
}

#[test]
fn a_key_of_the_wrong_kind_is_declined() {
    let env = openssl_only();
    let ec = PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap();
    let rsa = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    assert!(matches!(
        env.encrypt_key_transport(KeyTransportAlgorithm::RsaOaepSha256, &spki(&ec), &[0; 32]),
        Err(Error::Unrecognized)
    ));
    assert!(matches!(
        env.encrypt_key_agreement(
            KeyAgreementAlgorithm::EcdhSha256,
            KeyWrapAlgorithm::Aes256,
            &spki(&rsa),
            None,
            &[0; 32]
        ),
        Err(Error::Unrecognized)
    ));
    assert!(matches!(
        env.encrypt_kem(
            KdfAlgorithm::HkdfSha256,
            KeyWrapAlgorithm::Aes256,
            &spki(&rsa),
            None,
            &[0; 32]
        ),
        Err(Error::Unrecognized)
    ));
}

#[test]
fn associated_data_for_cbc_is_refused() {
    let env = openssl_only();
    assert!(matches!(
        env.encrypt_content(ContentEncryptionAlgorithm::Aes128Cbc, MESSAGE, Some(b"aad")),
        Err(Error::InvalidInput(_))
    ));
}
