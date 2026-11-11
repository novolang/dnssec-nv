# dnssec-nv

DNSSEC lets a resolver check that the records in a DNS answer are the ones
the zone's owner signed. The zone publishes public keys (DNSKEY records),
signs each set of records with them (RRSIG records), and its parent
publishes a digest of the zone's key (a DS record), so that trust passes
down from one key the resolver already holds, the **trust anchor**, to the
answer. The specifications are
[RFC 4033](https://www.rfc-editor.org/rfc/rfc4033),
[RFC 4034](https://www.rfc-editor.org/rfc/rfc4034) and
[RFC 4035](https://www.rfc-editor.org/rfc/rfc4035), with the
clarifications of [RFC 6840](https://www.rfc-editor.org/rfc/rfc6840) and
the hashed denial of existence of
[RFC 5155](https://www.rfc-editor.org/rfc/rfc5155). This package is that
check with no network under it: the records come from the caller, the time
is a number the caller passes, and the answer is one of the four states of
RFC 4033, secure, insecure, bogus or indeterminate.

## Checking the root trust anchor

The program below takes the root zone's key-signing key published in 2024,
computes its key tag and checks it against the trust anchor that the
package holds, the DS record that IANA publishes.

```novo
use std.bytes
use dnsrr
use dnskey
use dnsvalid

// The root zone's KSK-2024: flags 257, protocol 3, algorithm 8, then the key.
fn ksk_2024() -> [u8]
    let key = "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc="
    dnsrr.cat([1 as u8, 1 as u8, 3 as u8, 8 as u8], bytes.to_byte_list(bytes.from_base64(key) ?? bytes.zeros(0)))

fn main() [io]
    let rdata = ksk_2024()
    let anchor = dnsvalid.root_trust_anchor()
    println("key tag ${dnskey.key_tag(rdata)}, anchor tag ${anchor.key_tag}")
    println("the anchor names this key: ${dnskey.ds_matches(anchor, dnsrr.name_text("."), rdata)}")
```

A full validation hands `validate_answer` the anchors, one `ZoneLink` for
each zone from the root down to the zone that signs the answer, the RRset
and its RRSIG records, and the time:

```
let v = dnsvalid.validate_answer([dnsvalid.root_trust_anchor()], links, rrset, rrsigs, now)
println(dnsvalid.state_name(v.state))     // secure, insecure, bogus or indeterminate
println(dnsvalid.reason_name(v.reason))   // why, in words
```

## What DNSSEC is

**A key** is a DNSKEY record: flags, a protocol (always 3), an algorithm
number and the public key. Bit 8 of the flags (value 256) marks a zone key,
bit 15 (value 1) marks a secure entry point, the key a parent's DS record
names, and bit 7 (value 128) marks a key that has been revoked (RFC 5011).
The **key tag** is a 16-bit sum over the RDATA that lets a signature name
the key that made it. Two keys can have the same tag, so it is a hint and
the verifier tries every key with that tag and algorithm.

**A signature** is an RRSIG record that covers one RRset, the records with
the same owner, class and type. It names the covered type, the algorithm,
the number of labels in the owner (which is how a wildcard expansion is
told from an exact answer), the original TTL, the expiry and the inception
times, the key tag, the signer's name and the signature. The signature is
over the RRSIG's own fields followed by the RRset in **canonical form**
(RFC 4034 section 6): the owner in lower case, the TTL set to the original
TTL, the names inside the RDATA of the types RFC 4034 section 6.2 lists
in lower case, and the records sorted by their RDATA as unsigned byte
strings.

**A chain** is a DS record in the parent that holds a digest of the child's
key, signed by the parent's keys, and a DNSKEY set in the child that
includes that key and is signed by it. The root zone's key is the anchor.
A zone whose parent proves that it has no DS record is **insecure**, a zone
the resolver expects to be signed but whose records do not check is
**bogus**, and a validation that lacks the records it needs is
**indeterminate**.

**Denial of existence** is how a signed zone says that a name or a type is
not there. An NSEC record names the next name in the zone's canonical
order and lists the types its owner has, so a name between the two is
absent. NSEC3 does the same over the SHA-1 hashes of the names, so the zone
cannot be listed by walking it, and the flag `opt-out` lets a zone skip the
hashes of unsigned delegations.

| Quantity | Value |
| --- | --- |
| DNSKEY algorithms verified | 8 (RSA/SHA-256), 13 (ECDSA P-256), 15 (Ed25519) |
| DS digest types computed | 1 (SHA-1), 2 (SHA-256), 4 (SHA-384) |
| NSEC3 hash | 1 (SHA-1), with the iteration count and salt of the record |
| RSA key | 2048 bits or more, as `rsa-nv` requires |
| Signature times | seconds since 1970, compared with the serial arithmetic of RFC 4034 section 3.1.5 |
| Root trust anchor | KSK-2024, key tag 38696, DS digest type 2 |

## Install

```
novo pkg add dnssec-nv
```

## What the package contains

| Module | Contents |
| --- | --- |
| `dnsrr` | The record (`DnsRr`) and the names: the canonical order of RFC 4034 section 6.1, the label count for an RRSIG, the lower-casing of the names in the RDATA by type, the sorted canonical form of an RRset, and the wildcard helpers. |
| `dnskey` | The DNSKEY and DS records: parsing, the key tag, the RSA public key split of RFC 3110, the DS digest (SHA-1, SHA-256, SHA-384), the match of a DS against a key, and the delete forms of RFC 8078 for CDS and CDNSKEY. |
| `dnsrrsig` | The RRSIG record: parsing, the validity window, the data a signature covers, and `verify` against a key, which answers a verdict number and a name for it. |
| `dnsnsec` | The type bitmaps, the NSEC and NSEC3 records, the base32hex of RFC 4648, the NSEC3 hash, and the denial proofs for a name that does not exist, a type that does not exist, a wildcard, an insecure delegation and an opt-out span. |
| `dnsvalid` | The chain from a trust anchor through the zone links, the check of an RRset against its zone's keys, the four states and the reasons for them, and the root trust anchor. |

## How to choose an entry point

**`dnsvalid.validate_answer` is for a resolver that has the records.** It
checks the chain and the answer in one call and says which of the four
states it is and why.

**`dnsvalid.validate_chain` and `validate_rrset` are for a program that
validates in steps**, such as one that keeps the keys of a zone it has
checked and tests many RRsets against them.

**`dnsrrsig.verify` is for a program that checks one signature** against one
key, and `verify_signature` is the same check without the time window.

**`dnsnsec` is for the answer that says no.** The proof is a set of NSEC or
NSEC3 records from the response. Authenticate them with `validate_rrset`
first; the proofs read them as they are.

## The rules a user needs

1. **The time is a number the caller passes.** `now` is seconds since 1970.
   A signature is valid from its inception to its expiry, inclusive, by the
   serial arithmetic of RFC 4034 section 3.1.5. The package reads no clock.
2. **The records are the caller's.** `ZoneLink` holds, for one zone, its
   DNSKEY RRset and the signatures over it, and its DS RRset in the parent
   and the signatures over that. A link is in order from the trust anchor
   down. A link that is not below the one before it is bogus.
3. **No anchors, or no links, is indeterminate.** The package cannot say
   that the data is secure or wrong when it was given nothing to check.
4. **A DS RRset or a key set that names only what the package does not
   verify is insecure.** RFC 6840 section 5.2 says a validator treats such
   a zone as unsigned. See *What is not included* for the list.
5. **A signature that does not verify is bogus.** `Validation.detail` holds
   the verdict of `dnsrrsig.verify`: an expired window, a key that does
   not match, a signature that fails, an RRset that is not the one the
   signature covers.
6. **The signer must be the zone the chain ends at.** A signature whose
   signer is another zone is bogus (`REASON_WRONG_SIGNER`), and an RRset
   owner outside the zone is indeterminate.
7. **A wildcard expansion is told by the label count.** An RRSIG whose
   Labels field is less than the number of labels in the owner was made for
   `*.` plus the rightmost labels, and the data it covers is rebuilt that
   way (RFC 4035 section 5.3.2). Whether the response also proves that no
   closer name exists is `nsec_wildcard_expansion_ok` and
   `nsec3_wildcard_expansion_ok`.
8. **A denial answers a number.** `nsec_denial` and `nsec3_denial` answer
   `DENIAL_NXDOMAIN`, `DENIAL_NODATA`, `DENIAL_NODATA_WILDCARD`,
   `DENIAL_NO_DS`, `DENIAL_OPT_OUT` or `DENIAL_NO_PROOF`. A set that proves
   less than it must answers `DENIAL_NO_PROOF`, never a partial yes.
   The opt-out flag decides the answer only for a DS query (RFC 5155
   section 8.6); for a name that does not exist it does not change the
   proof (section 8.4).
9. **An NSEC3 hash is computed from the name as given.** `nsec3_hash` takes
   the iteration count and the salt of the record; an iteration count above
   what the caller allows is the caller's to refuse before calling.
10. **Names are `DnsName` values of `dns-codec-nv`.** A record that came
    out of a decoded message becomes a `DnsRr` with `dnsrr.rr_of_record`.
11. **A reader answers an error value or a zero for what is not there.** It
    does not trap. `dnskey_parse`, `ds_parse`, `rrsig_parse`, `nsec_parse`
    and `nsec3_parse` answer a `Result` with a `DnssecError`, and a name
    that is compressed in the RDATA of a record is such an error.

## Running on a microcontroller

This package is `core` and makes no claim for the embedded tier. The check
is a list of records and the keys and signatures are byte lists, and the
three signature packages it verifies with, `rsa-nv`, `p256-nv` and
`ed25519-nv`, are arithmetic over lists and big integers that carry no
embedded annotation. A device that must check one signature can call those
packages itself; the canonical form and the chain walk here need the
allocator. A rewrite on fixed-capacity types would be a second release with
its own probe.

## What is not included

- **Algorithms 5, 7 and 10** (RSA/SHA-1 and RSA/SHA-512). `rsa-nv` 0.1.0
  verifies with SHA-256 and SHA-384 only and rejects a modulus under 2048
  bits, so a 1024-bit RSA key, still common in older zones, gives
  `VERDICT_ALGORITHM` or `VERDICT_KEY_REFUSED`.
- **Algorithms 14 and 16** (ECDSA P-384 and Ed448). No package verifies them.
  The keys parse; the verdict is `VERDICT_ALGORITHM`.
- **The GOST digest** (DS digest type 3) and GOST signatures.
- **Signing.** The package reads and verifies; it holds no private key.
- **A resolver, a cache and the clock.** The package does no input or
  output.
- **The A6 record's canonical form,** which RFC 6840 section 5.1 withdrew.
- **Trust anchor management** (RFC 5011 timers, RFC 8509 signalling). The
  root anchor is a constant; where else anchors come from is the caller's.
- **A limit on the NSEC3 iteration count** (RFC 9276 advises a validator to
  treat a high count as insecure). `nsec3_hash` computes what it is given.

## Findings

The Ed25519 examples of [RFC 8080](https://www.rfc-editor.org/rfc/rfc8080)
section 6 do not verify as printed. Their RRSIG text omits the algorithm
and the signatures were made over data with a Labels field of 3, while the
owner `example.com.` has two labels. `verify` refuses them as RFC 4035
section 5.3.1 requires, because the Labels field is greater than the
owner's label count. `verify_signature`, which checks the cryptography
without that rule, accepts both with the Labels field the signatures were
made with. The tests cover both.

## Related packages

- [dns-codec-nv](https://novo-lang.org/packages/dns-codec-nv) decodes the
  messages the records come out of.
- [rsa-nv](https://novo-lang.org/packages/rsa-nv),
  [p256-nv](https://novo-lang.org/packages/p256-nv) and
  [ed25519-nv](https://novo-lang.org/packages/ed25519-nv) do the signature
  arithmetic.
- [dhcpv6-nv](https://novo-lang.org/packages/dhcpv6-nv) and
  [ipfix-nv](https://novo-lang.org/packages/ipfix-nv) are protocol packages
  of the same kind.

## Tests

```bash
novo test tests/dnssec_wire_tests.nv      # key tags, DS digests, canonical form, bitmaps, parsers
novo test tests/dnssec_verify_tests.nv    # RRSIG data, and the RSA, P-256 and Ed25519 signatures of the RFCs
novo test tests/dnssec_denial_tests.nv    # NSEC and NSEC3 proofs from RFC 4035 and RFC 5155
novo test tests/dnssec_chain_tests.nv     # chains from a trust anchor, the four states, the reasons
bash tests/coverage.sh                    # line coverage over src/, merged across the suites
```

The vectors are the RFCs' own: the DNSKEY, RRSIG and DS examples of RFC 4034
appendix B and section 5.4, the signed zone of RFC 4035 appendix A with
the responses of appendix B, the NSEC3 zone of RFC 5155 appendix A with the
responses of appendix B and the hashes it lists, the ECDSA P-256 example of
[RFC 6605](https://www.rfc-editor.org/rfc/rfc6605) and the Ed25519 examples
of RFC 8080. The root key and its tag, 38696, are those of IANA's
`root-anchors.xml` for KSK-2024. The chain tests use zones made by
`tests/make_chain_vectors.py`, a signer written apart from the package
(Python's `cryptography` package, Ed25519 at the root, P-256 for
`example.` and RSA-2048 for `sub.example.`), so that an accepted signature
was made by another reading of the RFCs. The RSA key is made afresh on
each run of the script; the test file holds one run's output and the tag
that belongs to it.

## Licence

Apache-2.0. See `LICENSE`.

<!-- docs/writing-a-readme.md is the style guide for this page. -->
