# Changelog
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html), except that
an increase to the minimum supported Rust version is not treated as a breaking change.

## [0.1.0-rc.1] - 2026-10-31

Initial release. Calculates SHA-1/224/256/384/512 digests and verifies RSA PKCS #1 v1.5,
RSASSA-PSS and ECDSA certificate signatures through the system's OpenSSL 3, and pure ML-DSA and
SLH-DSA through OpenSSL 3.5 and later, through all three of certval's hashing and verification
interfaces. Uses OpenSSL's default library context, so a system configured for FIPS routes every
operation through the FIPS provider; `OpenSslCrypto::fips_mode_enabled` reports whether it is.
MSRV 1.88.
