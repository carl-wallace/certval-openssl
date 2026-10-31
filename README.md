# certval-openssl

An OpenSSL crypto provider for [certval](https://github.com/carl-wallace/rust-pki). It supplies
implementations of the hashing and signature verification callbacks that a `PkiEnvironment`
dispatches through, so certification path validation can be performed with the system's OpenSSL 3,
including its FIPS provider where the system has one configured, rather than the in-process software
implementation.

```rust
use certval::PkiEnvironment;
use certval_openssl::OpenSslCrypto;

let mut pe = PkiEnvironment::default();

// Registering before populate_5280_pki_environment puts OpenSSL ahead of the software
// implementations, so it is consulted first and software answers only what it declined.
pe.add_calculate_hash_callback(OpenSslCrypto::new());
pe.add_verify_signature_message_callback(OpenSslCrypto::new());
pe.add_verify_signature_digest_callback(OpenSslCrypto::new());

pe.populate_5280_pki_environment();
```

The crate links the system's OpenSSL through the `openssl` crate and never enables its `vendored`
feature: a vendored build is compiled into the binary from source and is never the validated module
a deployment is installed with. OpenSSL 3.0 or later is required.

The provider holds no state. Each verification decodes the issuer's key with OpenSSL, verifies, and
frees the key.

## Registration is additive

`PkiEnvironment` consults registered implementations in order and stops at the first verdict. The
provider reports a rejection only when OpenSSL judged the signature invalid; anything else it
declines, and a declined verification falls through to the next implementation. That lets OpenSSL
answer for the algorithms its configured providers offer while software covers the rest.

It also means registering the provider does not by itself guarantee that every verification reaches
OpenSSL. A caller who requires that must make the registration exclusive:

```rust
pe.populate_5280_pki_environment();
pe.clear_verify_signature_message_callbacks();
pe.clear_verify_signature_digest_callbacks();
pe.add_verify_signature_message_callback(OpenSslCrypto::new());
pe.add_verify_signature_digest_callback(OpenSslCrypto::new());
```

## FIPS

The provider uses OpenSSL's default library context, so which implementation answers is the system's
OpenSSL configuration's decision, not this crate's. A system configured for FIPS, meaning an
`openssl.cnf` that activates the `fips` provider and sets `default_properties = fips=yes` as a
distribution's FIPS mode does, routes every hash and verification through the FIPS provider.
`OpenSslCrypto::fips_mode_enabled()` reports whether the default properties require `fips=yes`.

Whether a particular FIPS provider build is validated is a question for NIST's CMVP list. Distributions
that ship one (RHEL, and Ubuntu Pro) document how to turn their FIPS mode on.

## Algorithm coverage

| Signature algorithm | Notes |
|---|---|
| RSA PKCS #1 v1.5, SHA-224/256/384/512 | |
| RSASSA-PSS, SHA-224/256/384/512 | MGF1 hash and salt length taken from the parameters |
| ECDSA, SHA-224/256/384/512 | any curve OpenSSL decodes from the key |
| ML-DSA-44/65/87 (pure) | OpenSSL 3.5 or later; message interface only |
| SLH-DSA, all twelve parameter sets (pure) | OpenSSL 3.5 or later; message interface only |

| Hash | |
|---|---|
| SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 | |

Anything else is declined, and software answers it. The deliberate declines:

- **RSASSA-PSS relying on RFC 4055's SHA-1 defaults** for the hash or the mask, or naming SHA-1. An
  omitted salt length takes the RFC 4055 default of 20, as certval's software verifier reads it.
- **A PKCS #1 v1.5 signature under a key identified as `id-RSASSA-PSS`.** RFC 4055 restricts such a
  key to PSS, and certval's software verifier rejects the combination, so it gives that verdict.
- **ML-DSA and SLH-DSA where OpenSSL is older than 3.5**, which has neither. The key fails to
  decode, the provider declines, and software answers.
- **HashML-DSA and HashSLH-DSA**, the pre-hash variants, and any ML-DSA or SLH-DSA identifier carrying
  parameters, which RFC 9881 and RFC 9909 forbid. A key must be identified by the same object
  identifier as its signature.

OpenSSL takes the PSS mask's hash separately from the message hash, so it verifies combinations
certval's software verifier declines (SHA-256 with an MGF1-SHA-512 mask, say). That is capability the
provider adds, not a disagreement.

The digest interface calls `EVP_PKEY_verify` directly rather than through `PkeyCtx::verify`. OpenSSL
documents a return of 0 as "the signature did not verify", but `PkeyCtx::verify` reports a 0 as an
error whenever OpenSSL left anything on its error queue, which it does for an invalid ECDSA signature.
Through the wrapper, a bad signature would look like a refusal and fall through to software.

## Testing

`cargo test` runs the unit tests and the signature tests with no setup. The signature tests verify
ECDSA signatures made by RustCrypto with fixed keys, and RSA and RSASSA-PSS signatures from keys
OpenSSL generates, and check every verdict against certval's software verifier where it has one.
Each good signature is also checked with a changed message and with a changed signature, which must
be **rejections**, not refusals.

The collection tests verify certificates through the provider and compare against software. No
certificates are carried in this repository; the collections are named by environment variables, and
a test whose collection is not set reports that and passes.

| Variable | Meaning |
|---|---|
| `CERTVAL_OPENSSL_RSA_CERTS` | directory of RSA-signed certificates |
| `CERTVAL_OPENSSL_ECDSA_CERTS` | directory of ECDSA-signed certificates |
| `CERTVAL_OPENSSL_PSS_CERTS` | directory of RSASSA-PSS-signed certificates |
| `CERTVAL_OPENSSL_MLDSA_CERTS` | directory of ML-DSA-signed certificates |
| `CERTVAL_OPENSSL_SLHDSA_CERTS` | directories of SLH-DSA-signed certificates, separated as `PATH` is |
| `CERTVAL_OPENSSL_EXPECT_FIPS` | when set, the tests fail unless OpenSSL requires `fips=yes` |

```sh
export EX=../rust-pki/certval/tests/examples
export CERTVAL_OPENSSL_RSA_CERTS=$EX/PKITS_data_2048/certs
export CERTVAL_OPENSSL_ECDSA_CERTS=$EX/PKITS_data_p256/certs
export CERTVAL_OPENSSL_PSS_CERTS=$EX/rsapss
export CERTVAL_OPENSSL_MLDSA_CERTS=$EX/pkits_ml_dsa_44/certs
export CERTVAL_OPENSSL_SLHDSA_CERTS=$EX/pkits_slh_dsa_sha2_128f/certs:$EX/pkits_slh_dsa_shake_256f/certs

cargo test --features pqc -- --nocapture
```

The assertion in each case is **agreement** with software, not success. Where the linked OpenSSL is
3.5 or later, the ML-DSA and SLH-DSA tests also require that OpenSSL answered; where it is older,
they require that it answered nothing.

CI runs the suite three times on Ubuntu: against the runner's OpenSSL 3.0 with its default provider;
against an OpenSSL 3.5 built from source, which is where ML-DSA and SLH-DSA are exercised; and with
OpenSSL's FIPS provider built from a source release OpenSSL lists as validated, configured
with `default_properties = fips=yes` and `CERTVAL_OPENSSL_EXPECT_FIPS` set. See `.github/workflows/ci.yml`
for the configuration, which doubles as a worked example.

## Status

Run on macOS 26.6 against Homebrew's OpenSSL 3.6.5 (default provider) and rust-pki's PKITS
collections: OpenSSL answered all 389 RSA and 388 ECDSA verifications that software accepted, and all
394 for each of ML-DSA-44, -65 and -87 and for each of the twelve SLH-DSA parameter sets, with no
disagreements in either interface. **Not yet run against a FIPS
provider**; the CI job that does so has not run yet. Not yet published to crates.io.

certval is consumed from crates.io. A commented `[patch.crates-io]` line in `Cargo.toml` redirects
the dependency to a local checkout for developing both crates together.

## License

Apache-2.0 OR MIT.
