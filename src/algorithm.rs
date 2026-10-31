//! Translation from the algorithm identifiers certval presents to the digest and padding OpenSSL
//! needs.
//!
//! OpenSSL verifies over a message (`EVP_DigestVerify`, hashing inside OpenSSL) or over a digest
//! (`EVP_PKEY_verify` with a signature digest set), with the same digest and padding either way, so
//! both of certval's interfaces share one table.
//!
//! ML-DSA and SLH-DSA sit outside that table. Their pure forms sign the message itself, with no
//! separate hash, so they have a message form only, and their key is identified by the same
//! object identifier as the signature, so there is nothing to look up beyond recognizing it.

use certval::{
    PKIXALG_ECDSA_WITH_SHA224, PKIXALG_ECDSA_WITH_SHA256, PKIXALG_ECDSA_WITH_SHA384,
    PKIXALG_ECDSA_WITH_SHA512, PKIXALG_MGF1, PKIXALG_RSASSA_PSS, PKIXALG_SHA1, PKIXALG_SHA224,
    PKIXALG_SHA224_WITH_RSA_ENCRYPTION, PKIXALG_SHA256, PKIXALG_SHA256_WITH_RSA_ENCRYPTION,
    PKIXALG_SHA384, PKIXALG_SHA384_WITH_RSA_ENCRYPTION, PKIXALG_SHA512,
    PKIXALG_SHA512_WITH_RSA_ENCRYPTION,
};
use const_oid::db::fips204::{ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87};
use const_oid::db::fips205::{
    ID_SLH_DSA_SHAKE_128_F, ID_SLH_DSA_SHAKE_128_S, ID_SLH_DSA_SHAKE_192_F, ID_SLH_DSA_SHAKE_192_S,
    ID_SLH_DSA_SHAKE_256_F, ID_SLH_DSA_SHAKE_256_S, ID_SLH_DSA_SHA_2_128_F, ID_SLH_DSA_SHA_2_128_S,
    ID_SLH_DSA_SHA_2_192_F, ID_SLH_DSA_SHA_2_192_S, ID_SLH_DSA_SHA_2_256_F, ID_SLH_DSA_SHA_2_256_S,
};
use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use openssl::hash::MessageDigest;
use spki::AlgorithmIdentifierOwned;

/// A hash OpenSSL provides under a name certval uses.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Hash {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub(crate) fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        match *oid {
            PKIXALG_SHA1 => Some(Hash::Sha1),
            PKIXALG_SHA224 => Some(Hash::Sha224),
            PKIXALG_SHA256 => Some(Hash::Sha256),
            PKIXALG_SHA384 => Some(Hash::Sha384),
            PKIXALG_SHA512 => Some(Hash::Sha512),
            _ => None,
        }
    }

    pub(crate) fn len(self) -> usize {
        match self {
            Hash::Sha1 => 20,
            Hash::Sha224 => 28,
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
        }
    }

    pub(crate) fn digest(self) -> MessageDigest {
        match self {
            Hash::Sha1 => MessageDigest::sha1(),
            Hash::Sha224 => MessageDigest::sha224(),
            Hash::Sha256 => MessageDigest::sha256(),
            Hash::Sha384 => MessageDigest::sha384(),
            Hash::Sha512 => MessageDigest::sha512(),
        }
    }
}

/// How the signature is laid out over the digest.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Padding {
    /// RSA PKCS #1 v1.5.
    Pkcs1,
    /// RSASSA-PSS with MGF1 over `mgf_hash` and the given salt length.
    Pss { mgf_hash: Hash, salt_len: u32 },
    /// ECDSA, with the DER signature OpenSSL takes as it is.
    Ecdsa,
}

/// The hash and padding a signature algorithm identifier calls for.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Scheme {
    pub(crate) hash: Hash,
    pub(crate) padding: Padding,
}

/// The pure ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) parameter sets. The pre-hash variants,
/// HashML-DSA and HashSLH-DSA, have identifiers of their own and are not among them.
const PURE_PQC: [ObjectIdentifier; 15] = [
    ID_ML_DSA_44,
    ID_ML_DSA_65,
    ID_ML_DSA_87,
    ID_SLH_DSA_SHA_2_128_S,
    ID_SLH_DSA_SHA_2_128_F,
    ID_SLH_DSA_SHA_2_192_S,
    ID_SLH_DSA_SHA_2_192_F,
    ID_SLH_DSA_SHA_2_256_S,
    ID_SLH_DSA_SHA_2_256_F,
    ID_SLH_DSA_SHAKE_128_S,
    ID_SLH_DSA_SHAKE_128_F,
    ID_SLH_DSA_SHAKE_192_S,
    ID_SLH_DSA_SHAKE_192_F,
    ID_SLH_DSA_SHAKE_256_S,
    ID_SLH_DSA_SHAKE_256_F,
];

/// Returns whether `alg` is a pure ML-DSA or SLH-DSA signature, verified over the message with no
/// separate hash. RFC 9881 and RFC 9909 require the parameters to be absent, so an identifier
/// carrying any is not recognized.
pub(crate) fn is_pure_pqc(alg: &AlgorithmIdentifierOwned) -> bool {
    alg.parameters.is_none() && PURE_PQC.contains(&alg.oid)
}

/// Returns the scheme for a signature algorithm identifier, or `None` when the provider declines
/// it. ML-DSA and SLH-DSA are among the declined, since they have no digest form; see
/// [`is_pure_pqc`] for the message form.
pub(crate) fn signature_scheme(alg: &AlgorithmIdentifierOwned) -> Option<Scheme> {
    let scheme = |hash, padding| Some(Scheme { hash, padding });
    match alg.oid {
        PKIXALG_SHA224_WITH_RSA_ENCRYPTION => scheme(Hash::Sha224, Padding::Pkcs1),
        PKIXALG_SHA256_WITH_RSA_ENCRYPTION => scheme(Hash::Sha256, Padding::Pkcs1),
        PKIXALG_SHA384_WITH_RSA_ENCRYPTION => scheme(Hash::Sha384, Padding::Pkcs1),
        PKIXALG_SHA512_WITH_RSA_ENCRYPTION => scheme(Hash::Sha512, Padding::Pkcs1),

        PKIXALG_ECDSA_WITH_SHA224 => scheme(Hash::Sha224, Padding::Ecdsa),
        PKIXALG_ECDSA_WITH_SHA256 => scheme(Hash::Sha256, Padding::Ecdsa),
        PKIXALG_ECDSA_WITH_SHA384 => scheme(Hash::Sha384, Padding::Ecdsa),
        PKIXALG_ECDSA_WITH_SHA512 => scheme(Hash::Sha512, Padding::Ecdsa),

        PKIXALG_RSASSA_PSS => pss_scheme(alg),

        _ => None,
    }
}

/// Reads RSASSA-PSS parameters into a scheme.
///
/// OpenSSL takes the hash, the MGF1 hash and the salt length separately, so it can honor any
/// SHA-2 combination. A SHA-1 hash or mask is declined: RFC 4055 defaults both to SHA-1, so a
/// parameter block omitting either is declined too. An omitted salt length takes the RFC 4055
/// default of 20, which is how certval's software verifier reads it.
fn pss_scheme(alg: &AlgorithmIdentifierOwned) -> Option<Scheme> {
    let encoded = alg.parameters.as_ref()?.to_der().ok()?;
    let pss = RsaPssParams::from_der(&encoded).ok()?;

    let hash = Hash::from_oid(&pss.hash?.oid)?;

    let mask_gen = pss.mask_gen?;
    if mask_gen.oid != PKIXALG_MGF1 {
        return None;
    }
    let mgf_hash = mask_gen
        .parameters
        .as_ref()?
        .decode_as::<AlgorithmIdentifierOwned>()
        .ok()?;
    let mgf_hash = Hash::from_oid(&mgf_hash.oid)?;

    if hash == Hash::Sha1 || mgf_hash == Hash::Sha1 {
        return None;
    }
    if pss.trailer_field.unwrap_or(1) != 1 {
        return None;
    }

    Some(Scheme {
        hash,
        padding: Padding::Pss {
            mgf_hash,
            salt_len: pss.salt_len.unwrap_or(20),
        },
    })
}

/// The parameter block carried by an RSASSA-PSS algorithm identifier.
#[derive(der::Sequence)]
pub(crate) struct RsaPssParams {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) hash: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) mask_gen: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) salt_len: Option<u32>,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) trailer_field: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::asn1::Any;

    fn hash_alg(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid,
            parameters: Some(Any::null()),
        }
    }

    fn pss(
        hash: Option<ObjectIdentifier>,
        mgf_hash: Option<ObjectIdentifier>,
        salt_len: Option<u32>,
    ) -> AlgorithmIdentifierOwned {
        let params = RsaPssParams {
            hash: hash.map(hash_alg),
            mask_gen: mgf_hash.map(|h| AlgorithmIdentifierOwned {
                oid: PKIXALG_MGF1,
                parameters: Some(Any::encode_from(&hash_alg(h)).unwrap()),
            }),
            salt_len,
            trailer_field: None,
        };
        AlgorithmIdentifierOwned {
            oid: PKIXALG_RSASSA_PSS,
            parameters: Some(Any::encode_from(&params).unwrap()),
        }
    }

    fn plain(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid,
            parameters: None,
        }
    }

    #[test]
    fn every_pkcs1_and_ecdsa_oid_maps() {
        for (oid, hash, padding) in [
            (
                PKIXALG_SHA224_WITH_RSA_ENCRYPTION,
                Hash::Sha224,
                Padding::Pkcs1,
            ),
            (
                PKIXALG_SHA256_WITH_RSA_ENCRYPTION,
                Hash::Sha256,
                Padding::Pkcs1,
            ),
            (
                PKIXALG_SHA384_WITH_RSA_ENCRYPTION,
                Hash::Sha384,
                Padding::Pkcs1,
            ),
            (
                PKIXALG_SHA512_WITH_RSA_ENCRYPTION,
                Hash::Sha512,
                Padding::Pkcs1,
            ),
            (PKIXALG_ECDSA_WITH_SHA224, Hash::Sha224, Padding::Ecdsa),
            (PKIXALG_ECDSA_WITH_SHA256, Hash::Sha256, Padding::Ecdsa),
            (PKIXALG_ECDSA_WITH_SHA384, Hash::Sha384, Padding::Ecdsa),
            (PKIXALG_ECDSA_WITH_SHA512, Hash::Sha512, Padding::Ecdsa),
        ] {
            assert_eq!(
                signature_scheme(&plain(oid)),
                Some(Scheme { hash, padding }),
                "{oid}"
            );
        }
    }

    #[test]
    fn unknown_algorithm_is_declined() {
        let ed25519 = ObjectIdentifier::new_unwrap("1.3.101.112");
        assert!(signature_scheme(&plain(ed25519)).is_none());
        assert!(!is_pure_pqc(&plain(ed25519)));
    }

    #[test]
    fn pure_pqc_has_no_digest_form() {
        for oid in PURE_PQC {
            assert!(is_pure_pqc(&plain(oid)), "{oid}");
            assert!(signature_scheme(&plain(oid)).is_none(), "{oid}");
        }
    }

    #[test]
    fn pure_pqc_with_parameters_is_not_recognized() {
        let alg = AlgorithmIdentifierOwned {
            oid: ID_ML_DSA_65,
            parameters: Some(Any::null()),
        };
        assert!(!is_pure_pqc(&alg));
    }

    #[test]
    fn hash_ml_dsa_is_not_pure() {
        // id-hash-ml-dsa-44-with-sha512 signs a digest, so it is not verified as pure ML-DSA.
        let hash_ml_dsa_44 = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.32");
        assert!(!is_pure_pqc(&plain(hash_ml_dsa_44)));
    }

    #[test]
    fn pss_parameters_are_carried_through() {
        let s =
            signature_scheme(&pss(Some(PKIXALG_SHA256), Some(PKIXALG_SHA384), Some(20))).unwrap();
        assert_eq!(s.hash, Hash::Sha256);
        assert_eq!(
            s.padding,
            Padding::Pss {
                mgf_hash: Hash::Sha384,
                salt_len: 20
            }
        );
    }

    #[test]
    fn pss_omitted_salt_takes_the_rfc_4055_default() {
        let s = signature_scheme(&pss(Some(PKIXALG_SHA512), Some(PKIXALG_SHA512), None)).unwrap();
        assert_eq!(
            s.padding,
            Padding::Pss {
                mgf_hash: Hash::Sha512,
                salt_len: 20
            }
        );
    }

    #[test]
    fn pss_sha1_or_defaulted_hash_or_mask_is_declined() {
        assert!(signature_scheme(&pss(None, Some(PKIXALG_SHA256), Some(32))).is_none());
        assert!(signature_scheme(&pss(Some(PKIXALG_SHA256), None, Some(32))).is_none());
        assert!(signature_scheme(&pss(Some(PKIXALG_SHA1), Some(PKIXALG_SHA1), Some(20))).is_none());
        assert!(
            signature_scheme(&pss(Some(PKIXALG_SHA256), Some(PKIXALG_SHA1), Some(32))).is_none()
        );
        assert!(signature_scheme(&plain(PKIXALG_RSASSA_PSS)).is_none());
    }
}
