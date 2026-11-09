//! The provider's implementations of certval-cms's interfaces, under the `cms` feature: content
//! encryption and decryption, the three kinds of recipient encryption, and [`OpenSslRecipientKey`],
//! a recipient credential whose private key OpenSSL holds.
//!
//! Each operation is performed whole by OpenSSL: the content-encryption key, IV and nonce come from
//! OpenSSL's random number generator, ECDH runs its shared secret through OpenSSL's X9.63 KDF, and
//! the KEM's shared secret goes to OpenSSL's HKDF. As with verification, an OpenSSL error is the
//! provider declining, so the environment passes the request to the next implementation.

use std::ffi::CStr;

use certval_cms::{
    content_decryption_parameters, ecc_cms_shared_info, kem_other_info, CmsEnvironment,
    ContentEncryptionAlgorithm, ContentEncryptionOutput, ContentParameters, DecryptContent,
    EncryptContent, EncryptKem, EncryptKeyAgreement, EncryptKeyTransport, Error, GcmParameters,
    KdfAlgorithm, KemOutput, KeyAgreeOutput, KeyAgreementAlgorithm, KeyTransportAlgorithm,
    KeyWrapAlgorithm, RecipientCredential, Result, SigningCredential, SigningKey,
};
use const_oid::db::{
    fips203::{ID_ALG_ML_KEM_1024, ID_ALG_ML_KEM_512, ID_ALG_ML_KEM_768},
    rfc5912::{ID_EC_PUBLIC_KEY, RSA_ENCRYPTION},
};
use der::{
    asn1::{Any, OctetString},
    Encode, Tag,
};
use log::{debug, trace};
use openssl::bn::BigNumContext;
use openssl::cipher::{Cipher, CipherRef};
use openssl::cipher_ctx::{CipherCtx, CipherCtxFlags};
use openssl::ec::{EcKey, EcPoint, PointConversionForm};
use openssl::error::ErrorStack;
use openssl::kdf::{hkdf, HkdfMode};
use openssl::md::{Md, MdRef};
use openssl::pkey::{Id, PKey, Private, Public};
use openssl::pkey_ctx::PkeyCtx;
use openssl::rsa::Padding;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::Certificate;
use zeroize::Zeroizing;

use crate::algorithm::{is_pure_pqc, signature_scheme, Padding as SignaturePadding};
use crate::provider::apply_padding;
use crate::OpenSslCrypto;

/// Length in octets of the GCM nonce generated for a message, the length RFC 5084 recommends.
const GCM_NONCE_LEN: usize = 12;

/// Length in octets of the GCM authentication tag produced for a message.
const GCM_TAG_LEN: usize = 16;

/// Length in octets of an AES-CBC IV.
const CBC_IV_LEN: usize = 16;

/// Logs an OpenSSL error and turns it into a decline.
fn declined(what: &str, e: ErrorStack) -> Error {
    debug!("OpenSSL could not {what}: {e}");
    Error::Unrecognized
}

fn random(len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(vec![0u8; len]);
    openssl::rand::rand_bytes(&mut buf).map_err(|e| declined("generate random bytes", e))?;
    Ok(buf)
}

/// Decodes `spki`, declining a key OpenSSL does not decode or that is not of type `id`.
fn public_key(spki: &SubjectPublicKeyInfoOwned, id: Id) -> Result<PKey<Public>> {
    let key = PKey::public_key_from_der(&spki.to_der()?)
        .map_err(|e| declined("decode a public key", e))?;
    if key.id() != id {
        return Err(Error::Unrecognized);
    }
    Ok(key)
}

/// Wraps `cek` under `kek` with AES key wrap (RFC 3394).
fn aes_key_wrap(wrap: KeyWrapAlgorithm, kek: &[u8], cek: &[u8]) -> Result<Vec<u8>> {
    let cipher = match wrap {
        KeyWrapAlgorithm::Aes128 => Cipher::aes_128_wrap(),
        KeyWrapAlgorithm::Aes192 => Cipher::aes_192_wrap(),
        KeyWrapAlgorithm::Aes256 => Cipher::aes_256_wrap(),
        _ => return Err(Error::Unrecognized),
    };
    let wrapped = (|| -> core::result::Result<_, ErrorStack> {
        let mut ctx = CipherCtx::new()?;
        ctx.set_flags(CipherCtxFlags::FLAG_WRAP_ALLOW);
        // No IV: OpenSSL uses RFC 3394's default initial value.
        ctx.encrypt_init(Some(cipher), Some(kek), None)?;
        let mut wrapped = vec![];
        ctx.cipher_update_vec(cek, &mut wrapped)?;
        ctx.cipher_final_vec(&mut wrapped)?;
        Ok(wrapped)
    })();
    wrapped.map_err(|e| declined("wrap a key", e))
}

fn cbc_encrypt(
    alg: ContentEncryptionAlgorithm,
    cipher: &CipherRef,
    key: Zeroizing<Vec<u8>>,
    plaintext: &[u8],
) -> Result<ContentEncryptionOutput> {
    let iv = random(CBC_IV_LEN)?;
    let ciphertext = (|| -> core::result::Result<_, ErrorStack> {
        let mut ctx = CipherCtx::new()?;
        ctx.encrypt_init(Some(cipher), Some(&key), Some(&iv))?;
        let mut ciphertext = vec![];
        ctx.cipher_update_vec(plaintext, &mut ciphertext)?;
        ctx.cipher_final_vec(&mut ciphertext)?;
        Ok(ciphertext)
    })()
    .map_err(|e| declined("encrypt content", e))?;
    Ok(ContentEncryptionOutput {
        ciphertext,
        key,
        algorithm: AlgorithmIdentifierOwned {
            oid: alg.oid(),
            parameters: Some(Any::new(Tag::OctetString, iv.as_slice())?),
        },
        tag: None,
    })
}

fn gcm_encrypt(
    alg: ContentEncryptionAlgorithm,
    cipher: &CipherRef,
    key: Zeroizing<Vec<u8>>,
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Result<ContentEncryptionOutput> {
    let nonce = random(GCM_NONCE_LEN)?;
    let (ciphertext, tag) = (|| -> core::result::Result<_, ErrorStack> {
        let mut ctx = CipherCtx::new()?;
        ctx.encrypt_init(Some(cipher), None, None)?;
        ctx.set_iv_length(GCM_NONCE_LEN)?;
        ctx.encrypt_init(None, Some(&key), Some(&nonce))?;
        if let Some(aad) = aad {
            ctx.cipher_update(aad, None)?;
        }
        // Room for the final call's block, so the vector is not regrown and copied.
        let mut ciphertext = Vec::with_capacity(plaintext.len() + GCM_TAG_LEN);
        ctx.cipher_update_vec(plaintext, &mut ciphertext)?;
        ctx.cipher_final_vec(&mut ciphertext)?;
        let mut tag = vec![0u8; GCM_TAG_LEN];
        ctx.tag(&mut tag)?;
        Ok((ciphertext, tag))
    })()
    .map_err(|e| declined("encrypt content", e))?;
    let params = GcmParameters {
        nonce: OctetString::new(nonce.as_slice())?,
        icv_len: GCM_TAG_LEN as u8,
    };
    Ok(ContentEncryptionOutput {
        ciphertext,
        key,
        algorithm: AlgorithmIdentifierOwned {
            oid: alg.oid(),
            parameters: Some(Any::encode_from(&params)?),
        },
        tag: Some(tag),
    })
}

impl EncryptContent for OpenSslCrypto {
    fn encrypt_content(
        &self,
        _env: &CmsEnvironment,
        alg: ContentEncryptionAlgorithm,
        plaintext: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<ContentEncryptionOutput> {
        if aad.is_some() && !alg.is_authenticated() {
            return Err(Error::InvalidInput(String::from(
                "associated data given for an algorithm that does not authenticate",
            )));
        }
        let key = random(alg.key_len())?;
        let encrypted = match alg {
            ContentEncryptionAlgorithm::Aes128Cbc => {
                cbc_encrypt(alg, Cipher::aes_128_cbc(), key, plaintext)
            }
            ContentEncryptionAlgorithm::Aes192Cbc => {
                cbc_encrypt(alg, Cipher::aes_192_cbc(), key, plaintext)
            }
            ContentEncryptionAlgorithm::Aes256Cbc => {
                cbc_encrypt(alg, Cipher::aes_256_cbc(), key, plaintext)
            }
            ContentEncryptionAlgorithm::Aes128Gcm => {
                gcm_encrypt(alg, Cipher::aes_128_gcm(), key, plaintext, aad)
            }
            ContentEncryptionAlgorithm::Aes192Gcm => {
                gcm_encrypt(alg, Cipher::aes_192_gcm(), key, plaintext, aad)
            }
            ContentEncryptionAlgorithm::Aes256Gcm => {
                gcm_encrypt(alg, Cipher::aes_256_gcm(), key, plaintext, aad)
            }
            _ => Err(Error::Unrecognized),
        }?;
        trace!("OpenSSL encrypted content with {alg:?}");
        Ok(encrypted)
    }
}

/// The OAEP hash a key transport algorithm uses, or `None` for RSAES-PKCS1-v1_5.
fn oaep_md(alg: KeyTransportAlgorithm) -> Result<Option<&'static MdRef>> {
    match alg {
        KeyTransportAlgorithm::RsaPkcs1v15 => Ok(None),
        KeyTransportAlgorithm::RsaOaepSha1 => Ok(Some(Md::sha1())),
        KeyTransportAlgorithm::RsaOaepSha256 => Ok(Some(Md::sha256())),
        KeyTransportAlgorithm::RsaOaepSha384 => Ok(Some(Md::sha384())),
        KeyTransportAlgorithm::RsaOaepSha512 => Ok(Some(Md::sha512())),
        _ => Err(Error::Unrecognized),
    }
}

/// Sets the padding for key transport: PKCS #1 v1.5, or OAEP with MGF1 using the same hash and an
/// empty label (RFC 4055, section 4.1).
fn set_key_transport_padding<T>(
    ctx: &mut PkeyCtx<T>,
    oaep_md: Option<&MdRef>,
) -> core::result::Result<(), ErrorStack> {
    match oaep_md {
        None => ctx.set_rsa_padding(Padding::PKCS1),
        Some(md) => {
            ctx.set_rsa_padding(Padding::PKCS1_OAEP)?;
            ctx.set_rsa_oaep_md(md)?;
            ctx.set_rsa_mgf1_md(md)
        }
    }
}

impl EncryptKeyTransport for OpenSslCrypto {
    fn encrypt_key_transport(
        &self,
        _env: &CmsEnvironment,
        alg: KeyTransportAlgorithm,
        spki: &SubjectPublicKeyInfoOwned,
        cek: &[u8],
    ) -> Result<Vec<u8>> {
        // RFC 4055 restricts a key identified as id-RSASSA-PSS to signatures.
        if spki.algorithm.oid != RSA_ENCRYPTION {
            return Err(Error::Unrecognized);
        }
        let oaep_md = oaep_md(alg)?;
        let key = public_key(spki, Id::RSA)?;
        let encrypted = (|| -> core::result::Result<_, ErrorStack> {
            let mut ctx = PkeyCtx::new(&key)?;
            ctx.encrypt_init()?;
            set_key_transport_padding(&mut ctx, oaep_md)?;
            let mut encrypted = vec![];
            ctx.encrypt_to_vec(cek, &mut encrypted)?;
            Ok(encrypted)
        })()
        .map_err(|e| declined("perform key transport", e))?;
        trace!("OpenSSL performed key transport with {alg:?}");
        Ok(encrypted)
    }
}

/// The digest, by OpenSSL name, that a key agreement scheme's X9.63 KDF uses.
fn x963_digest(alg: KeyAgreementAlgorithm) -> Result<&'static CStr> {
    match alg {
        KeyAgreementAlgorithm::EcdhSha256 => Ok(c"SHA256"),
        KeyAgreementAlgorithm::EcdhSha384 => Ok(c"SHA384"),
        KeyAgreementAlgorithm::EcdhSha512 => Ok(c"SHA512"),
        _ => Err(Error::Unrecognized),
    }
}

/// The digest an HKDF algorithm uses.
fn hkdf_md(kdf: KdfAlgorithm) -> Result<&'static MdRef> {
    match kdf {
        KdfAlgorithm::HkdfSha256 => Ok(Md::sha256()),
        KdfAlgorithm::HkdfSha384 => Ok(Md::sha384()),
        KdfAlgorithm::HkdfSha512 => Ok(Md::sha512()),
        _ => Err(Error::Unrecognized),
    }
}

impl EncryptKeyAgreement for OpenSslCrypto {
    /// Ephemeral-static ECDH on the recipient's curve, which may be any named curve OpenSSL decodes.
    fn encrypt_key_agreement(
        &self,
        _env: &CmsEnvironment,
        alg: KeyAgreementAlgorithm,
        wrap: KeyWrapAlgorithm,
        spki: &SubjectPublicKeyInfoOwned,
        ukm: Option<&[u8]>,
        cek: &[u8],
    ) -> Result<KeyAgreeOutput> {
        if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
            return Err(Error::Unrecognized);
        }
        let digest = x963_digest(alg)?;
        let recipient = public_key(spki, Id::EC)?;
        let shared_info = ecc_cms_shared_info(wrap, ukm)?;
        let (ephemeral_public_key, kek) = (|| -> core::result::Result<_, ErrorStack> {
            let recipient_ec = recipient.ec_key()?;
            let group = recipient_ec.group();
            let ephemeral = EcKey::generate(group)?;
            let mut bn_ctx = BigNumContext::new()?;
            let ephemeral_public_key = ephemeral.public_key().to_bytes(
                group,
                PointConversionForm::UNCOMPRESSED,
                &mut bn_ctx,
            )?;
            let ephemeral = PKey::from_ec_key(ephemeral)?;

            let mut ctx = PkeyCtx::new(&ephemeral)?;
            ctx.derive_init()?;
            ctx.derive_set_peer(&recipient)?;
            crate::ffi::set_ecdh_x963_kdf(&mut ctx, digest, wrap.kek_len(), &shared_info)?;
            let mut kek = Zeroizing::new(vec![0u8; wrap.kek_len()]);
            let len = ctx.derive(Some(&mut kek))?;
            kek.truncate(len);
            Ok((ephemeral_public_key, kek))
        })()
        .map_err(|e| declined("perform key agreement", e))?;
        if kek.len() != wrap.kek_len() {
            return Err(Error::Crypto(format!(
                "OpenSSL derived {} octets for a {}-octet key-encryption key",
                kek.len(),
                wrap.kek_len()
            )));
        }
        let encrypted_key = aes_key_wrap(wrap, &kek, cek)?;
        trace!("OpenSSL performed key agreement with {alg:?} and {wrap:?}");
        Ok(KeyAgreeOutput {
            ephemeral_public_key,
            encrypted_key,
        })
    }
}

impl EncryptKem for OpenSslCrypto {
    /// ML-KEM, which needs OpenSSL 3.5 or later; an older OpenSSL does not decode the key, and the
    /// provider declines.
    fn encrypt_kem(
        &self,
        _env: &CmsEnvironment,
        kdf: KdfAlgorithm,
        wrap: KeyWrapAlgorithm,
        spki: &SubjectPublicKeyInfoOwned,
        ukm: Option<&[u8]>,
        cek: &[u8],
    ) -> Result<KemOutput> {
        if ![ID_ALG_ML_KEM_512, ID_ALG_ML_KEM_768, ID_ALG_ML_KEM_1024].contains(&spki.algorithm.oid)
        {
            return Err(Error::Unrecognized);
        }
        let md = hkdf_md(kdf)?;
        let key = PKey::public_key_from_der(&spki.to_der()?)
            .map_err(|e| declined("decode a KEM public key", e))?;
        // RFC 9629, section 5: the input keying material is the shared secret, and the salt absent.
        let info = kem_other_info(wrap, ukm)?;
        let (kem_ct, kek) = (|| -> core::result::Result<_, ErrorStack> {
            let mut ctx = PkeyCtx::new(&key)?;
            let (kem_ct, ss) = crate::ffi::encapsulate(&mut ctx)?;
            let mut kek = Zeroizing::new(vec![0u8; wrap.kek_len()]);
            hkdf(
                md,
                &ss,
                None,
                Some(&info),
                HkdfMode::ExtractAndExpand,
                None,
                &mut kek,
            )?;
            Ok((kem_ct, kek))
        })()
        .map_err(|e| declined("perform a KEM", e))?;
        let encrypted_key = aes_key_wrap(wrap, &kek, cek)?;
        trace!("OpenSSL performed a KEM with {kdf:?} and {wrap:?}");
        Ok(KemOutput {
            kem_ct,
            encrypted_key,
        })
    }
}

/// The failure every content decryption error is reported as, so that a wrong key, malformed
/// padding and a tag that does not verify cannot be told apart.
fn decryption_failed() -> Error {
    Error::Crypto(String::from("content decryption failed"))
}

/// Unwraps `wrapped` under `kek` with AES key wrap (RFC 3394). An integrity failure, which is what
/// a wrong key-encryption key produces, is [`Error::Crypto`].
fn aes_key_unwrap(
    wrap: KeyWrapAlgorithm,
    kek: &[u8],
    wrapped: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = match wrap {
        KeyWrapAlgorithm::Aes128 => Cipher::aes_128_wrap(),
        KeyWrapAlgorithm::Aes192 => Cipher::aes_192_wrap(),
        KeyWrapAlgorithm::Aes256 => Cipher::aes_256_wrap(),
        _ => return Err(Error::Unrecognized),
    };
    let mut ctx = CipherCtx::new().map_err(|e| declined("unwrap a key", e))?;
    ctx.set_flags(CipherCtxFlags::FLAG_WRAP_ALLOW);
    ctx.decrypt_init(Some(cipher), Some(kek), None)
        .map_err(|e| declined("unwrap a key", e))?;
    let mut cek = Zeroizing::new(vec![]);
    ctx.cipher_update_vec(wrapped, &mut cek)
        .and_then(|_| ctx.cipher_final_vec(&mut cek))
        .map_err(|e| {
            debug!("OpenSSL could not unwrap a key: {e}");
            Error::Crypto(String::from("key unwrap failed"))
        })?;
    Ok(cek)
}

fn cbc_decrypt(
    cipher: &CipherRef,
    iv: &[u8],
    key: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut ctx = CipherCtx::new().map_err(|e| declined("decrypt content", e))?;
    ctx.decrypt_init(Some(cipher), Some(key), Some(iv))
        .map_err(|e| declined("decrypt content", e))?;
    let mut plaintext = Zeroizing::new(vec![]);
    ctx.cipher_update_vec(ciphertext, &mut plaintext)
        .and_then(|_| ctx.cipher_final_vec(&mut plaintext))
        .map_err(|_| decryption_failed())?;
    Ok(plaintext)
}

fn gcm_decrypt(
    cipher: &CipherRef,
    nonce: &[u8],
    key: &[u8],
    ciphertext: &[u8],
    aad: Option<&[u8]>,
    tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut ctx = CipherCtx::new().map_err(|e| declined("decrypt content", e))?;
    (|| -> core::result::Result<(), ErrorStack> {
        ctx.decrypt_init(Some(cipher), None, None)?;
        ctx.set_iv_length(nonce.len())?;
        ctx.decrypt_init(None, Some(key), Some(nonce))?;
        ctx.set_tag(tag)
    })()
    .map_err(|e| declined("decrypt content", e))?;
    // Room for the final call's block, so the vector is not regrown, which would leave a copy of
    // the plaintext in freed memory.
    let mut plaintext = Zeroizing::new(Vec::with_capacity(ciphertext.len() + GCM_TAG_LEN));
    (|| -> core::result::Result<(), ErrorStack> {
        if let Some(aad) = aad {
            ctx.cipher_update(aad, None)?;
        }
        ctx.cipher_update_vec(ciphertext, &mut plaintext)?;
        ctx.cipher_final_vec(&mut plaintext)?;
        Ok(())
    })()
    .map_err(|_| decryption_failed())?;
    Ok(plaintext)
}

impl DecryptContent for OpenSslCrypto {
    fn decrypt_content(
        &self,
        _env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        tag: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let (content_alg, parameters) = content_decryption_parameters(alg, key, aad, tag)?;
        let plaintext = match (content_alg, parameters, tag) {
            (ContentEncryptionAlgorithm::Aes128Cbc, ContentParameters::Cbc { iv }, _) => {
                cbc_decrypt(Cipher::aes_128_cbc(), &iv, key, ciphertext)
            }
            (ContentEncryptionAlgorithm::Aes192Cbc, ContentParameters::Cbc { iv }, _) => {
                cbc_decrypt(Cipher::aes_192_cbc(), &iv, key, ciphertext)
            }
            (ContentEncryptionAlgorithm::Aes256Cbc, ContentParameters::Cbc { iv }, _) => {
                cbc_decrypt(Cipher::aes_256_cbc(), &iv, key, ciphertext)
            }
            (
                ContentEncryptionAlgorithm::Aes128Gcm,
                ContentParameters::Gcm { nonce },
                Some(tag),
            ) => gcm_decrypt(Cipher::aes_128_gcm(), &nonce, key, ciphertext, aad, tag),
            (
                ContentEncryptionAlgorithm::Aes192Gcm,
                ContentParameters::Gcm { nonce },
                Some(tag),
            ) => gcm_decrypt(Cipher::aes_192_gcm(), &nonce, key, ciphertext, aad, tag),
            (
                ContentEncryptionAlgorithm::Aes256Gcm,
                ContentParameters::Gcm { nonce },
                Some(tag),
            ) => gcm_decrypt(Cipher::aes_256_gcm(), &nonce, key, ciphertext, aad, tag),
            _ => Err(Error::Unrecognized),
        }?;
        trace!("OpenSSL decrypted content with {content_alg:?}");
        Ok(plaintext)
    }
}

/// A [`RecipientCredential`] whose private key is held by OpenSSL, so that each recipient type's
/// whole operation is performed there: RSA key transport, ECDH with the X9.63 KDF and AES key
/// unwrap, or ML-KEM decapsulation (OpenSSL 3.5 or later) with HKDF and AES key unwrap.
///
/// The key is an OpenSSL `PKey`, so it can come from anything OpenSSL loads keys from, e.g. a
/// PKCS #8 file or a provider-backed store.
pub struct OpenSslRecipientKey {
    certificate: Certificate,
    key: PKey<Private>,
}

impl OpenSslRecipientKey {
    /// A credential for `key`, identified by `certificate`. The key must be the private half of the
    /// certificate's public key.
    pub fn new(certificate: Certificate, key: PKey<Private>) -> Result<Self> {
        let public = key
            .public_key_to_der()
            .map_err(|e| declined("encode a public key", e))?;
        if public
            != certificate
                .tbs_certificate()
                .subject_public_key_info()
                .to_der()?
        {
            return Err(Error::InvalidInput(String::from(
                "the private key is not the certificate's",
            )));
        }
        Ok(Self { certificate, key })
    }

    /// A credential for the PKCS #8 (RFC 5958) private key `der`, identified by `certificate`.
    pub fn from_pkcs8_der(certificate: Certificate, der: &[u8]) -> Result<Self> {
        let key =
            PKey::private_key_from_pkcs8(der).map_err(|e| declined("decode a private key", e))?;
        Self::new(certificate, key)
    }

    /// The originator's ephemeral key, as a public key on this key's curve. RFC 5753 does not
    /// require the originator's algorithm identifier to name the curve, and OpenSSL omits it, so
    /// the point is read on the recipient's curve.
    fn originator_key(&self, originator: &SubjectPublicKeyInfoOwned) -> Result<PKey<Public>> {
        let ec = self
            .key
            .ec_key()
            .map_err(|e| declined("use an EC key", e))?;
        let group = ec.group();
        (|| -> core::result::Result<_, ErrorStack> {
            let mut bn_ctx = BigNumContext::new()?;
            let point = EcPoint::from_bytes(
                group,
                originator.subject_public_key.raw_bytes(),
                &mut bn_ctx,
            )?;
            PKey::from_ec_key(EcKey::from_public_key(group, &point)?)
        })()
        .map_err(|e| {
            debug!("OpenSSL could not decode an originator key: {e}");
            Error::Crypto(String::from("key agreement failed"))
        })
    }
}

impl RecipientCredential for OpenSslRecipientKey {
    fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    fn decrypt_key_transport(
        &self,
        _env: &CmsEnvironment,
        alg: KeyTransportAlgorithm,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if self.key.id() != Id::RSA {
            return Err(Error::Unrecognized);
        }
        let oaep_md = oaep_md(alg)?;
        let mut ctx = PkeyCtx::new(&self.key).map_err(|e| declined("perform key transport", e))?;
        ctx.decrypt_init()
            .and_then(|_| set_key_transport_padding(&mut ctx, oaep_md))
            .map_err(|e| declined("perform key transport", e))?;
        let mut cek = Zeroizing::new(vec![]);
        ctx.decrypt_to_vec(encrypted_key, &mut cek).map_err(|e| {
            debug!("OpenSSL could not decrypt a key transport: {e}");
            Error::Crypto(String::from("key transport failed"))
        })?;
        trace!("OpenSSL decrypted a key transport with {alg:?}");
        Ok(cek)
    }

    fn decrypt_key_agreement(
        &self,
        _env: &CmsEnvironment,
        alg: KeyAgreementAlgorithm,
        wrap: KeyWrapAlgorithm,
        originator: &SubjectPublicKeyInfoOwned,
        ukm: Option<&[u8]>,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if self.key.id() != Id::EC {
            return Err(Error::Unrecognized);
        }
        let digest = x963_digest(alg)?;
        let originator = self.originator_key(originator)?;
        let shared_info = ecc_cms_shared_info(wrap, ukm)?;
        let mut kek = Zeroizing::new(vec![0u8; wrap.kek_len()]);
        let len = (|| -> core::result::Result<_, ErrorStack> {
            let mut ctx = PkeyCtx::new(&self.key)?;
            ctx.derive_init()?;
            ctx.derive_set_peer(&originator)?;
            crate::ffi::set_ecdh_x963_kdf(&mut ctx, digest, wrap.kek_len(), &shared_info)?;
            ctx.derive(Some(&mut kek))
        })()
        .map_err(|e| declined("perform key agreement", e))?;
        if len != wrap.kek_len() {
            return Err(Error::Crypto(format!(
                "OpenSSL derived {len} octets for a {}-octet key-encryption key",
                wrap.kek_len()
            )));
        }
        let cek = aes_key_unwrap(wrap, &kek, encrypted_key)?;
        trace!("OpenSSL decrypted a key agreement with {alg:?} and {wrap:?}");
        Ok(cek)
    }

    fn decrypt_kem(
        &self,
        _env: &CmsEnvironment,
        kdf: KdfAlgorithm,
        wrap: KeyWrapAlgorithm,
        kem_ct: &[u8],
        ukm: Option<&[u8]>,
        encrypted_key: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let key_alg = self
            .certificate
            .tbs_certificate()
            .subject_public_key_info()
            .algorithm
            .oid;
        if ![ID_ALG_ML_KEM_512, ID_ALG_ML_KEM_768, ID_ALG_ML_KEM_1024].contains(&key_alg) {
            return Err(Error::Unrecognized);
        }
        let md = hkdf_md(kdf)?;
        let info = kem_other_info(wrap, ukm)?;
        let mut ctx = PkeyCtx::new(&self.key).map_err(|e| declined("perform a KEM", e))?;
        let ss = crate::ffi::decapsulate(&mut ctx, kem_ct).map_err(|e| {
            debug!("OpenSSL could not decapsulate: {e}");
            Error::Crypto(String::from("decapsulation failed"))
        })?;
        let mut kek = Zeroizing::new(vec![0u8; wrap.kek_len()]);
        hkdf(
            md,
            &ss,
            None,
            Some(&info),
            HkdfMode::ExtractAndExpand,
            None,
            &mut kek,
        )
        .map_err(|e| declined("derive a key-encryption key", e))?;
        let cek = aes_key_unwrap(wrap, &kek, encrypted_key)?;
        trace!("OpenSSL decrypted a KEM with {kdf:?} and {wrap:?}");
        Ok(cek)
    }
}

/// A [`SigningKey`] whose private key is held by OpenSSL, with no certificate: e.g. a key signing
/// its own certificate request or a self-signed certificate. It signs as [`OpenSslSigningKey`]
/// does: RSA PKCS #1 v1.5 or RSASSA-PSS, ECDSA, or, on OpenSSL 3.5 or later, pure ML-DSA and
/// SLH-DSA, each wholly in OpenSSL, hashing included.
pub struct OpenSslKey {
    public_key: SubjectPublicKeyInfoOwned,
    key: PKey<Private>,
}

impl OpenSslKey {
    /// A key for `key`, whose public key OpenSSL encodes.
    pub fn new(key: PKey<Private>) -> Result<Self> {
        let public = key
            .public_key_to_der()
            .map_err(|e| declined("encode a public key", e))?;
        Ok(Self {
            public_key: der::Decode::from_der(&public)?,
            key,
        })
    }

    /// A key for the PKCS #8 (RFC 5958) private key `der`.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        let key =
            PKey::private_key_from_pkcs8(der).map_err(|e| declined("decode a private key", e))?;
        Self::new(key)
    }

    fn sign(&self, alg: &AlgorithmIdentifierOwned, message: &[u8]) -> Result<Vec<u8>> {
        let signer = if is_pure_pqc(alg) {
            // RFC 9881 and RFC 9909: the signature's identifier is the key's, and the signature
            // carries no context string, which is OpenSSL's default.
            if alg.oid != self.public_key.algorithm.oid {
                return Err(Error::Unrecognized);
            }
            openssl::sign::Signer::new_without_digest(&self.key)
        } else {
            let Some(scheme) = signature_scheme(alg) else {
                return Err(Error::Unrecognized);
            };
            let key_fits = match scheme.padding {
                SignaturePadding::Pkcs1 => self.key.id() == Id::RSA,
                SignaturePadding::Pss { .. } => {
                    self.key.id() == Id::RSA || self.key.id() == Id::RSA_PSS
                }
                SignaturePadding::Ecdsa => self.key.id() == Id::EC,
            };
            if !key_fits {
                return Err(Error::Unrecognized);
            }
            openssl::sign::Signer::new(scheme.hash.digest(), &self.key).and_then(|mut signer| {
                apply_padding(&mut signer, scheme.padding)?;
                Ok(signer)
            })
        };
        let mut signer = signer.map_err(|e| declined("sign", e))?;
        let signature = signer.sign_oneshot_to_vec(message).map_err(|e| {
            debug!("OpenSSL could not sign: {e}");
            Error::Crypto(String::from("signing failed"))
        })?;
        trace!("OpenSSL signed with {}", alg.oid);
        Ok(signature)
    }
}

impl SigningKey for OpenSslKey {
    fn public_key(&self) -> &SubjectPublicKeyInfoOwned {
        &self.public_key
    }

    fn sign_message(
        &self,
        _env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        self.sign(alg, message)
    }
}

/// A [`SigningCredential`] whose private key is held by OpenSSL, signing SignedData with RSA PKCS #1
/// v1.5 or RSASSA-PSS, ECDSA, or, on OpenSSL 3.5 or later, pure ML-DSA and SLH-DSA, each wholly in
/// OpenSSL, hashing included. An [`OpenSslKey`] with its certificate.
pub struct OpenSslSigningKey {
    certificate: Certificate,
    key: OpenSslKey,
}

impl OpenSslSigningKey {
    /// A credential for `key`, identified by `certificate`. The key must be the private half of the
    /// certificate's public key.
    pub fn new(certificate: Certificate, key: PKey<Private>) -> Result<Self> {
        let key = OpenSslKey::new(key)?;
        if key.public_key != *certificate.tbs_certificate().subject_public_key_info() {
            return Err(Error::InvalidInput(String::from(
                "the private key is not the certificate's",
            )));
        }
        Ok(Self { certificate, key })
    }

    /// A credential for the PKCS #8 (RFC 5958) private key `der`, identified by `certificate`.
    pub fn from_pkcs8_der(certificate: Certificate, der: &[u8]) -> Result<Self> {
        let key =
            PKey::private_key_from_pkcs8(der).map_err(|e| declined("decode a private key", e))?;
        Self::new(certificate, key)
    }
}

impl SigningCredential for OpenSslSigningKey {
    fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    fn sign_message(
        &self,
        _env: &CmsEnvironment,
        alg: &AlgorithmIdentifierOwned,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        self.key.sign(alg, message)
    }
}
