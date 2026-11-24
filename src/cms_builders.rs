//! Key management for cms's own recipient builders, through OpenSSL: [`OpenSslKeyEncryptor`] for
//! `KeyTransRecipientInfoBuilder`, and [`OpenSslKeyAgreement`] and [`OpenSslKeyWrap`] for
//! `KeyAgreeRecipientInfoBuilder`. These implement cms's traits directly, so a caller using cms's
//! builders without a certval-cms `CmsEnvironment` can have OpenSSL, or its FIPS provider, perform
//! the operation.
//!
//! The random number generator cms's builders pass is not used: OpenSSL draws the RSA padding and
//! the ephemeral key from its own generator, as a FIPS provider requires.

use certval_cms::{
    Error as CmsError, KeyAgreementAlgorithm, KeyTransportAlgorithm, KeyWrapAlgorithm,
};
use cms::builder::{self, KeyAgreement, KeyAgreementOutput};
use cms::enveloped_data::OriginatorPublicKey;
use const_oid::{DynAssociatedOid, ObjectIdentifier};
use der::asn1::BitString;
use log::debug;
use rsa::traits::RandomizedEncryptor;
use spki::{AlgorithmIdentifierOwned, DynAssociatedAlgorithmIdentifier, SubjectPublicKeyInfoOwned};
use x509_cert::Certificate;

use crate::cms::{aes_key_wrap, ecdh_x963, rsa_encrypt};

/// A certval-cms error as a cms builder error, which holds only a message.
fn builder_error(e: CmsError) -> builder::Error {
    match e {
        CmsError::Asn1(e) => builder::Error::Asn1(e),
        e => builder::Error::Builder(e.to_string()),
    }
}

/// RSA key transport to one recipient's key, by OpenSSL, for cms's `KeyTransRecipientInfoBuilder`:
/// RSAES-PKCS1-v1_5 or RSAES-OAEP, as the [`KeyTransportAlgorithm`] given says.
///
/// OpenSSL's FIPS 3.5 provider refuses RSAES-PKCS1-v1_5 encryption; the builder then fails, and
/// the reason is in the log.
#[derive(Clone, Debug)]
pub struct OpenSslKeyEncryptor {
    spki: SubjectPublicKeyInfoOwned,
    alg: KeyTransportAlgorithm,
}

impl OpenSslKeyEncryptor {
    /// Key transport with `alg` to the RSA key in `spki`.
    pub fn new(spki: SubjectPublicKeyInfoOwned, alg: KeyTransportAlgorithm) -> Self {
        Self { spki, alg }
    }

    /// Key transport with `alg` to the RSA key in `cert`.
    pub fn from_certificate(cert: &Certificate, alg: KeyTransportAlgorithm) -> Self {
        Self::new(
            cert.tbs_certificate().subject_public_key_info().clone(),
            alg,
        )
    }
}

impl RandomizedEncryptor for OpenSslKeyEncryptor {
    fn encrypt_with_rng<R: rsa::rand_core::TryCryptoRng + ?Sized>(
        &self,
        _rng: &mut R,
        msg: &[u8],
    ) -> rsa::Result<Vec<u8>> {
        rsa_encrypt(self.alg, &self.spki, msg).map_err(|e| {
            debug!("OpenSSL key transport with {:?} failed: {e}", self.alg);
            rsa::Error::Internal
        })
    }
}

impl DynAssociatedAlgorithmIdentifier for OpenSslKeyEncryptor {
    fn algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
        // Only encoding the OAEP parameters can fail.
        self.alg.algorithm_identifier().map_err(|e| match e {
            CmsError::Asn1(e) => spki::Error::Asn1(e),
            _ => spki::Error::Asn1(der::ErrorKind::Failed.into()),
        })
    }
}

/// Ephemeral-static ECDH with one recipient's EC key, on its curve, and the X9.63 KDF, by OpenSSL,
/// for cms's `KeyAgreeRecipientInfoBuilder`. The [`KeyAgreementAlgorithm`] given identifies the
/// scheme and the KDF's hash.
#[derive(Clone, Debug)]
pub struct OpenSslKeyAgreement {
    spki: SubjectPublicKeyInfoOwned,
    alg: KeyAgreementAlgorithm,
}

impl OpenSslKeyAgreement {
    /// Key agreement with `alg` with the EC key in `spki`.
    pub fn new(spki: SubjectPublicKeyInfoOwned, alg: KeyAgreementAlgorithm) -> Self {
        Self { spki, alg }
    }

    /// Key agreement with `alg` with the EC key in `cert`.
    pub fn from_certificate(cert: &Certificate, alg: KeyAgreementAlgorithm) -> Self {
        Self::new(
            cert.tbs_certificate().subject_public_key_info().clone(),
            alg,
        )
    }
}

impl DynAssociatedOid for OpenSslKeyAgreement {
    fn oid(&self) -> ObjectIdentifier {
        self.alg.oid()
    }
}

impl<R: ?Sized> KeyAgreement<R> for OpenSslKeyAgreement {
    fn agree(
        &self,
        shared_info: &[u8],
        kek_size: usize,
        _rng: &mut R,
    ) -> builder::Result<KeyAgreementOutput> {
        let (ephemeral_public_key, key_encryption_key) =
            ecdh_x963(self.alg, &self.spki, shared_info, kek_size).map_err(builder_error)?;
        Ok(KeyAgreementOutput {
            // RFC 5753, section 3.1.1: the ephemeral key is on the recipient's curve, which the
            // algorithm identifier names.
            originator_key: OriginatorPublicKey {
                algorithm: self.spki.algorithm.clone(),
                public_key: BitString::from_bytes(&ephemeral_public_key)?,
            },
            key_encryption_key,
        })
    }
}

/// AES key wrap (RFC 3394) by OpenSSL, for cms's `KeyAgreeRecipientInfoBuilder`.
#[derive(Clone, Copy, Debug)]
pub struct OpenSslKeyWrap {
    wrap: KeyWrapAlgorithm,
}

impl OpenSslKeyWrap {
    /// Key wrap with `wrap`.
    pub fn new(wrap: KeyWrapAlgorithm) -> Self {
        Self { wrap }
    }
}

impl builder::KeyWrapAlgorithm for OpenSslKeyWrap {
    fn algorithm_identifier(&self) -> AlgorithmIdentifierOwned {
        self.wrap.algorithm_identifier()
    }

    fn kek_size(&self) -> usize {
        self.wrap.kek_len()
    }

    fn try_wrap(&self, kek: &[u8], key: &[u8]) -> builder::Result<Vec<u8>> {
        aes_key_wrap(self.wrap, kek, key).map_err(builder_error)
    }
}
