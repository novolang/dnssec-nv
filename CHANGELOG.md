# Changelog

All notable changes to dnssec-nv are recorded here. The format is
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the pre-1.0 rule that a breaking change bumps the MINOR number.

## 0.1.0

First release.

### Added

- The DNSKEY and DS records of RFC 4034: parsing, the key tag of appendix B,
  the RSA public key split of RFC 3110, the DS digests SHA-1, SHA-256 and
  SHA-384, the match of a DS against a key, and the delete forms of RFC 8078
  for CDS and CDNSKEY.
- The canonical form of RFC 4034 section 6: the canonical order of names,
  the lower-casing of the names in the RDATA of the types the RFC lists,
  the sorted RRset, and the data an RRSIG covers, including the wildcard
  owner rebuilt from the Labels field.
- RRSIG verification with RSA/SHA-256 (algorithm 8), ECDSA P-256 (13) and
  Ed25519 (15), through `rsa-nv`, `p256-nv` and `ed25519-nv`, with the
  validity window by serial arithmetic. `verify_signature` checks the
  cryptography without the window and the Labels rule.
- The NSEC and NSEC3 records, NSEC3PARAM, the type bitmaps, base32hex, the
  NSEC3 hash, and the denial proofs of RFC 4035 section 5.4 and RFC 5155
  section 8: a name that does not exist, a type that does not exist, a
  wildcard, an insecure delegation and an opt-out span, and the checks of a
  wildcard expansion.
- The validation of a chain from a trust anchor through the zone links, the
  check of an RRset against its zone's keys, the states secure, insecure,
  bogus and indeterminate (RFC 4033 section 5, RFC 6840) with a reason for
  each, and the root trust anchor KSK-2024 (key tag 38696) as a constant.
- 94 tests with 100% line coverage over `src/`: the examples of RFC 4034,
  4035, 5155, 6605 and 8080, the root key of IANA's `root-anchors.xml`, and
  zones signed by an independent script (`tests/make_chain_vectors.py`).

### Known

- The Ed25519 examples of RFC 8080 section 6 verify only through
  `verify_signature`. Their signatures were made over data with a Labels
  field of 3 for the owner `example.com.`, which has 2 labels, and the
  printed RRSIG omits the algorithm; `verify` refuses them by RFC 4035
  section 5.3.1.
- `src/dnsnsec.nv` binds the element of a list before it reads a field
  from it at three sites, each marked
  `workaround(a-let-binding-of-a-list-field-two-projections-below-a-list-element-is-released-without-a-retain)`.
  The compiler releases a list bound two projections below a list element
  without a retain. The filing is
  `bugs/memory-perceus/a-let-binding-of-a-list-field-two-projections-below-a-list-element-is-released-without-a-retain.md`
  in the novo repository.
- One line is excluded from coverage with a `cov: skip` marker in
  `src/dnsrrsig.nv`: the refusal of a P-256 key by `public_key_from_bytes`,
  which only a coordinate that is not 32 bytes causes, and the package
  passes two of 32.

### Not included

- Algorithms 5, 7 and 10 (`rsa-nv` 0.1.0 has no SHA-1 or SHA-512 and
  requires a modulus of 2048 bits), algorithms 14 and 16, and the GOST digest.
- Signing, a resolver, a cache, trust anchor management and a limit on the
  NSEC3 iteration count.
- An embedded tier: the signature packages it depends on carry no embedded
  annotation.

This release requires novo 0.24.1 or later.
