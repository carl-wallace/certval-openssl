//! Decryption through this provider, crossed with certval-cms's RustCrypto implementation in both
//! directions: messages RustCrypto builds are decrypted with only this provider registered and an
//! [`OpenSslRecipientKey`], and messages this provider builds are decrypted by RustCrypto with a
//! [`SoftwareRecipientKey`]. The second direction checks the provider's encryption against an
//! implementation that shares no code with OpenSSL.
//!
//! Every key transport algorithm with every content encryption algorithm; ECDH on P-256, P-384 and
//! P-521 with each KDF hash and wrap; and ML-KEM with each parameter set, KDF and wrap (OpenSSL 3.5
//! or later), with and without user keying material.

#![cfg(feature = "cms")]

use certval_cms::{
    AuthEnvelopedDataBuilder, CmsEnvironment, ContentEncryptionAlgorithm, EnvelopedDataBuilder,
    Error, GcmParameters, KdfAlgorithm, KemRecipient, KeyAgreeRecipient, KeyAgreementAlgorithm,
    KeyTransRecipient, KeyTransportAlgorithm, KeyWrapAlgorithm, RecipientCredential,
    SoftwareRecipientKey,
};
use certval_openssl::{OpenSslCrypto, OpenSslRecipientKey};
use cms::{builder::RecipientInfoBuilder, cert::x509::attr::Attribute, content_info::ContentInfo};
use const_oid::db::rfc5911::{ID_CONTENT_TYPE, ID_DATA};
use der::{asn1::SetOfVec, Any, Decode};
use getrandom::SysRng;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{extension::SubjectKeyIdentifier, X509Builder, X509NameBuilder};
use rand_core::UnwrapErr;
use x509_cert::Certificate;

type Rng = UnwrapErr<SysRng>;

const MESSAGE: &[u8] =
    b"certval-openssl decryption, longer than one AES block so that padding is exercised";

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

const UKMS: [Option<&[u8]>; 2] = [None, Some(b"user keying material")];

/// OpenSSL 3.5.0, the first with ML-KEM, in OpenSSL's version number layout.
const OPENSSL_3_5: i64 = 0x3050_0000;

fn rng() -> Rng {
    UnwrapErr(SysRng)
}

/// RustCrypto for everything.
fn software() -> CmsEnvironment {
    let mut env = CmsEnvironment::new();
    env.populate_software();
    env
}

/// This provider for everything, so nothing falls through to software.
fn openssl_only() -> CmsEnvironment {
    let mut env = CmsEnvironment::new();
    env.add_encrypt_content_callback(OpenSslCrypto::new());
    env.add_decrypt_content_callback(OpenSslCrypto::new());
    env.add_encrypt_key_transport_callback(OpenSslCrypto::new());
    env.add_encrypt_key_agreement_callback(OpenSslCrypto::new());
    env.add_encrypt_kem_callback(OpenSslCrypto::new());
    env
}

/// A certificate for `key` with a subject key identifier, issued by a throwaway P-256 CA.
fn certificate(key: &PKey<Private>) -> Certificate {
    let ca = PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "certval-openssl recipient")
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

/// A recipient key, with the credential for each implementation.
struct Recipient {
    cert: Certificate,
    key: PKey<Private>,
}

impl Recipient {
    fn new(key: PKey<Private>) -> Self {
        Self {
            cert: certificate(&key),
            key,
        }
    }
    fn openssl(&self) -> OpenSslRecipientKey {
        OpenSslRecipientKey::new(self.cert.clone(), self.key.clone()).unwrap()
    }
    fn software(&self) -> SoftwareRecipientKey {
        SoftwareRecipientKey::from_pkcs8_der(
            self.cert.clone(),
            &self.key.private_key_to_pkcs8().unwrap(),
        )
        .unwrap()
    }
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

/// A message to one recipient: EnvelopedData for CBC, and AuthEnvelopedData with a content-type
/// authenticated attribute for GCM.
fn envelop<'e>(
    env: &'e CmsEnvironment,
    alg: ContentEncryptionAlgorithm,
    recipient: impl RecipientInfoBuilder<Rng = Rng> + 'e,
) -> ContentInfo {
    if alg.is_authenticated() {
        let mut builder = AuthEnvelopedDataBuilder::new(MESSAGE, alg).unwrap();
        builder.auth_attrs(content_type_attrs());
        builder
            .add_recipient(recipient)
            .build_content_info(env, &mut rng())
            .unwrap()
    } else {
        EnvelopedDataBuilder::new(MESSAGE, alg)
            .unwrap()
            .add_recipient(recipient)
            .build_content_info(env, &mut rng())
            .unwrap()
    }
}

/// Decrypts with `env` and `credential`, and checks the content.
fn assert_decrypts(
    env: &CmsEnvironment,
    ci: &ContentInfo,
    credential: &dyn RecipientCredential,
    name: &str,
) {
    let decrypted = env
        .decrypt_enveloped_data(ci, Some(credential))
        .unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(decrypted.content.as_slice(), MESSAGE, "{name}");
}

/// The two crossings: built by `software`, decrypted by `openssl`; and the reverse.
struct Crossing {
    software: CmsEnvironment,
    openssl: CmsEnvironment,
}

impl Crossing {
    fn new() -> Self {
        Self {
            software: software(),
            openssl: openssl_only(),
        }
    }
}

#[test]
fn key_transport_with_each_algorithm_and_content_encryption() {
    let envs = Crossing::new();
    let recipient = Recipient::new(PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap());
    let (openssl_key, software_key) = (recipient.openssl(), recipient.software());
    for alg in [
        KeyTransportAlgorithm::RsaPkcs1v15,
        KeyTransportAlgorithm::RsaOaepSha1,
        KeyTransportAlgorithm::RsaOaepSha256,
        KeyTransportAlgorithm::RsaOaepSha384,
        KeyTransportAlgorithm::RsaOaepSha512,
    ] {
        for content in CONTENT {
            let name = format!("{alg:?} {content:?}");
            let r = KeyTransRecipient::from_certificate(&envs.software, &recipient.cert, None, alg)
                .unwrap();
            let ci = envelop(&envs.software, content, r);
            assert_decrypts(
                &envs.openssl,
                &ci,
                &openssl_key,
                &format!("RustCrypto to OpenSSL, {name}"),
            );

            let r = KeyTransRecipient::from_certificate(&envs.openssl, &recipient.cert, None, alg)
                .unwrap();
            let ci = envelop(&envs.openssl, content, r);
            assert_decrypts(
                &envs.software,
                &ci,
                &software_key,
                &format!("OpenSSL to RustCrypto, {name}"),
            );
        }
    }
}

fn key_agreement(curve: Nid) {
    let envs = Crossing::new();
    let key =
        PKey::from_ec_key(EcKey::generate(&EcGroup::from_curve_name(curve).unwrap()).unwrap())
            .unwrap();
    let recipient = Recipient::new(key);
    let (openssl_key, software_key) = (recipient.openssl(), recipient.software());
    for alg in [
        KeyAgreementAlgorithm::EcdhSha256,
        KeyAgreementAlgorithm::EcdhSha384,
        KeyAgreementAlgorithm::EcdhSha512,
    ] {
        for wrap in WRAPS {
            for ukm in UKMS {
                let name = format!("{curve:?} {alg:?} {wrap:?} ukm={}", ukm.is_some());
                let r = KeyAgreeRecipient::from_certificate(
                    &envs.software,
                    &recipient.cert,
                    None,
                    alg,
                    wrap,
                    ukm.map(<[u8]>::to_vec),
                )
                .unwrap();
                let ci = envelop(&envs.software, ContentEncryptionAlgorithm::Aes256Gcm, r);
                assert_decrypts(
                    &envs.openssl,
                    &ci,
                    &openssl_key,
                    &format!("RustCrypto to OpenSSL, {name}"),
                );

                let r = KeyAgreeRecipient::from_certificate(
                    &envs.openssl,
                    &recipient.cert,
                    None,
                    alg,
                    wrap,
                    ukm.map(<[u8]>::to_vec),
                )
                .unwrap();
                let ci = envelop(&envs.openssl, ContentEncryptionAlgorithm::Aes128Cbc, r);
                assert_decrypts(
                    &envs.software,
                    &ci,
                    &software_key,
                    &format!("OpenSSL to RustCrypto, {name}"),
                );
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
    if openssl::version::number() < OPENSSL_3_5 {
        eprintln!(
            "skipped: {} is older than OpenSSL 3.5, the first with ML-KEM",
            openssl::version::version()
        );
        return;
    }
    let envs = Crossing::new();
    for name in [c"ML-KEM-512", c"ML-KEM-768", c"ML-KEM-1024"] {
        let recipient = Recipient::new(generate(name));
        let (openssl_key, software_key) = (recipient.openssl(), recipient.software());
        for kdf in [
            KdfAlgorithm::HkdfSha256,
            KdfAlgorithm::HkdfSha384,
            KdfAlgorithm::HkdfSha512,
        ] {
            for wrap in WRAPS {
                for ukm in UKMS {
                    let label = format!("{name:?} {kdf:?} {wrap:?} ukm={}", ukm.is_some());
                    let r = KemRecipient::from_certificate(
                        &envs.software,
                        &recipient.cert,
                        None,
                        kdf,
                        wrap,
                        ukm.map(<[u8]>::to_vec),
                    )
                    .unwrap();
                    let ci = envelop(&envs.software, ContentEncryptionAlgorithm::Aes256Cbc, r);
                    assert_decrypts(
                        &envs.openssl,
                        &ci,
                        &openssl_key,
                        &format!("RustCrypto to OpenSSL, {label}"),
                    );

                    let r = KemRecipient::from_certificate(
                        &envs.openssl,
                        &recipient.cert,
                        None,
                        kdf,
                        wrap,
                        ukm.map(<[u8]>::to_vec),
                    )
                    .unwrap();
                    let ci = envelop(&envs.openssl, ContentEncryptionAlgorithm::Aes192Gcm, r);
                    assert_decrypts(
                        &envs.software,
                        &ci,
                        &software_key,
                        &format!("OpenSSL to RustCrypto, {label}"),
                    );
                }
            }
        }
    }
}

#[test]
fn a_private_key_that_is_not_the_certificates_is_refused() {
    let a = Recipient::new(PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap());
    let b = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    assert!(matches!(
        OpenSslRecipientKey::new(a.cert.clone(), b),
        Err(Error::InvalidInput(_))
    ));
}

#[test]
fn a_changed_tag_fails_decryption() {
    let env = openssl_only();
    let recipient = Recipient::new(PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap());
    let r = KeyTransRecipient::from_certificate(
        &env,
        &recipient.cert,
        None,
        KeyTransportAlgorithm::RsaOaepSha256,
    )
    .unwrap();
    let ci = envelop(&env, ContentEncryptionAlgorithm::Aes256Gcm, r);
    let mut aed = cms::authenveloped_data::AuthEnvelopedData::from_der(
        &der::Encode::to_der(&ci.content).unwrap(),
    )
    .unwrap();
    let mut mac = aed.mac.as_bytes().to_vec();
    mac[0] ^= 1;
    aed.mac = der::asn1::OctetString::new(mac).unwrap();
    let changed = ContentInfo {
        content_type: ci.content_type,
        content: Any::encode_from(&aed).unwrap(),
    };
    match env.decrypt_enveloped_data(&changed, Some(&recipient.openssl())) {
        Err(Error::Crypto(e)) => assert_eq!(e, "content decryption failed"),
        other => panic!("{:?}", other.map(|_| ())),
    }
}

/// OpenSSL accepts a GCM tag of 1 to 16 octets; RFC 5084, section 3.2, allows a message 12 to 16.
/// A message whose GCMParameters gives 8, with the mac truncated to match, is refused before
/// OpenSSL sees it.
#[test]
fn a_tag_shorter_than_rfc_5084_allows_is_refused() {
    let env = openssl_only();
    let recipient = Recipient::new(PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap());
    let r = KeyTransRecipient::from_certificate(
        &env,
        &recipient.cert,
        None,
        KeyTransportAlgorithm::RsaOaepSha256,
    )
    .unwrap();
    let ci = envelop(&env, ContentEncryptionAlgorithm::Aes256Gcm, r);
    let mut aed = cms::authenveloped_data::AuthEnvelopedData::from_der(
        &der::Encode::to_der(&ci.content).unwrap(),
    )
    .unwrap();
    let alg = &mut aed.auth_encrypted_content_info.content_enc_alg;
    let mut params =
        GcmParameters::from_der(&der::Encode::to_der(alg.parameters.as_ref().unwrap()).unwrap())
            .unwrap();
    params.icv_len = 8;
    alg.parameters = Some(Any::encode_from(&params).unwrap());
    aed.mac = der::asn1::OctetString::new(&aed.mac.as_bytes()[..8]).unwrap();
    let shortened = ContentInfo {
        content_type: ci.content_type,
        content: Any::encode_from(&aed).unwrap(),
    };
    assert!(matches!(
        env.decrypt_enveloped_data(&shortened, Some(&recipient.openssl())),
        Err(Error::InvalidInput(_))
    ));
}
