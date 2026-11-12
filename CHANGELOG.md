# Changelog
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that
an increase to the minimum supported Rust version is not treated as a breaking change.

## [0.1.0-rc.1] - 2026-11-12

Initial release. Calculates SHA-1/224/256/384/512 digests and verifies RSA PKCS #1 v1.5,
RSASSA-PSS and ECDSA certificate signatures through the system's OpenSSL 3, and pure ML-DSA and
SLH-DSA through OpenSSL 3.5 and later, through all three of certval's hashing and verification
interfaces. Uses OpenSSL's default library context, so a system configured for FIPS routes every
operation through the FIPS provider; `OpenSslCrypto::fips_mode_enabled` reports whether it is.

A `cms` feature, under which `OpenSslCrypto` implements certval-cms's content encryption and
decryption, key transport, key agreement and KEM interfaces: AES-128/192/256 in CBC and GCM,
RSAES-PKCS1-v1_5 and RSAES-OAEP, ephemeral-static ECDH with the X9.63 KDF, and ML-KEM (OpenSSL 3.5
or later) with HKDF, the last two with AES key wrap. `OpenSslRecipientKey` decrypts each recipient
type, and `OpenSslSigningKey` signs SignedData, each with a private key OpenSSL holds. `OpenSslKey` is
the signing key without a certificate (certval-cms's `SigningKey`), e.g. to sign a certificate
request. `pqc` also turns on certval-cms's `pqc` under `cms`.

MSRV 1.89.
