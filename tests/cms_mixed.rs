//! Providers mixed in one environment: each plug point is given exactly one implementation, some
//! this provider's and some certval-cms's RustCrypto software, with nothing to fall back to, so each
//! operation can only have been performed by the one assigned it.
//!
//! | Plug point                                  | Implementation        |
//! |---------------------------------------------|-----------------------|
//! | content encryption                          | OpenSSL               |
//! | content decryption                          | RustCrypto            |
//! | key transport                               | RustCrypto            |
//! | key agreement                               | OpenSSL               |
//! | hashing and signature verification (certval)| OpenSSL               |
//! | the signer's key                            | RustCrypto            |
//! | the recipient's key, found through a source | OpenSSL               |
//!
//! A message is signed, enveloped to an RSA and an EC recipient, and unwrapped again.

#![cfg(feature = "cms")]

use std::sync::Arc;

use certval::PkiEnvironment;
use certval_cms::{
    decrypt_content_rust_crypto, encrypt_key_transport_rust_crypto, CmsEnvironment,
    ContentEncryptionAlgorithm, EnvelopedDataBuilder, KeyAgreeRecipient, KeyAgreementAlgorithm,
    KeyTransRecipient, KeyTransportAlgorithm, KeyWrapAlgorithm, Layer, SignedDataBuilder, Signer,
    SignerPolicy, SingleRecipientCredential, SoftwareSigningKey,
};
use certval_openssl::{OpenSslCrypto, OpenSslRecipientKey};
use const_oid::db::rfc5911::{ID_DATA, ID_SIGNED_DATA};
use der::{Decode, Encode};
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

const MESSAGE: &[u8] = b"certval-cms with providers mixed";

/// A certificate for `key` with a subject key identifier and serial number `serial`, issued by a
/// throwaway P-256 CA. Nothing is vetted here, so the CA need not be trusted.
fn certificate(key: &PKey<Private>, serial: u32) -> Certificate {
    let ca = PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
    )
    .unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "certval mixed providers")
        .unwrap();
    let name = name.build();
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap())
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

#[test]
fn one_message_through_providers_mixed_per_plug_point() {
    // Hashing and signature verification: OpenSSL alone.
    let mut pe = PkiEnvironment::default();
    pe.add_calculate_hash_callback(OpenSslCrypto::new());
    pe.add_verify_signature_message_callback(OpenSslCrypto::new());
    pe.add_verify_signature_digest_callback(OpenSslCrypto::new());

    let mut env = CmsEnvironment::new();
    env.set_pki_environment(Arc::new(pe));
    env.add_encrypt_content_callback(OpenSslCrypto::new());
    env.add_decrypt_content_callback(decrypt_content_rust_crypto);
    env.add_encrypt_key_transport_callback(encrypt_key_transport_rust_crypto);
    env.add_encrypt_key_agreement_callback(OpenSslCrypto::new());

    // The signer's key is held by RustCrypto.
    let signer_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let signer_cert = certificate(&signer_key, 1);
    let signer = SoftwareSigningKey::from_pkcs8_der(
        signer_cert,
        &signer_key.private_key_to_pkcs8().unwrap(),
    )
    .unwrap();

    // The recipients' keys are held by OpenSSL; the EC recipient's is registered as a source.
    let rsa_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let rsa_cert = certificate(&rsa_key, 2);
    let ec_key = PKey::from_ec_key(
        EcKey::generate(&EcGroup::from_curve_name(Nid::SECP384R1).unwrap()).unwrap(),
    )
    .unwrap();
    let ec_cert = certificate(&ec_key, 3);
    let rsa_recipient = OpenSslRecipientKey::new(rsa_cert.clone(), rsa_key).unwrap();
    env.add_recipient_credential_source(SingleRecipientCredential::new(Arc::new(
        OpenSslRecipientKey::new(ec_cert.clone(), ec_key).unwrap(),
    )));

    // Signed with the RustCrypto key, the message digest computed by OpenSSL.
    let signed = SignedDataBuilder::new(MESSAGE)
        .add_signer(Signer::explicit(&signer))
        .build(&env)
        .unwrap()
        .content_info;

    // Enveloped by OpenSSL's AES-GCM, to an RSA recipient by RustCrypto's key transport and an EC
    // recipient by OpenSSL's key agreement.
    let mut rng = UnwrapErr(SysRng);
    let signed_der = signed.content.to_der().unwrap();
    let mut builder =
        EnvelopedDataBuilder::new(&signed_der, ContentEncryptionAlgorithm::Aes256Cbc).unwrap();
    builder.content_type(ID_SIGNED_DATA);
    let enveloped = builder
        .add_recipient(
            KeyTransRecipient::from_certificate(
                &env,
                &rsa_cert,
                None,
                KeyTransportAlgorithm::RsaOaepSha256,
            )
            .unwrap(),
        )
        .add_recipient(
            KeyAgreeRecipient::from_certificate(
                &env,
                &ec_cert,
                None,
                KeyAgreementAlgorithm::EcdhSha384,
                KeyWrapAlgorithm::Aes256,
                None,
            )
            .unwrap(),
        )
        .build_content_info(&env, &mut rng)
        .unwrap();

    // Unwrapped by the EC recipient, its key found through the source; the content decrypted by
    // RustCrypto; the signature verified by OpenSSL.
    let unwrapped = env
        .unwrap_content_info(&enveloped, None, None, SignerPolicy::All)
        .unwrap();
    let [Layer::Enveloped(decrypted), Layer::Signed(verified)] = unwrapped.layers.as_slice() else {
        panic!("expected an enveloped layer, then a signed one");
    };
    assert_eq!(decrypted.recipient_index, 1);
    assert_eq!(verified.signers.len(), 1);
    assert_eq!(unwrapped.content_type, ID_DATA);
    assert_eq!(unwrapped.content, MESSAGE);

    // The RSA recipient decrypts it too, with its OpenSSL key passed directly.
    let unwrapped = env
        .unwrap_content_info(&enveloped, Some(&rsa_recipient), None, SignerPolicy::All)
        .unwrap();
    assert_eq!(unwrapped.content, MESSAGE);
}
