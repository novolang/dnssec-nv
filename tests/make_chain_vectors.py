#!/usr/bin/env python3
"""Make the signed zones that tests/dnssec_chain_tests.nv validates.

This is an independent signer: it builds the canonical form of an RRset
from RFC 4034 section 6 and RFC 4035 section 5.3.2 with its own code and
signs it with the `cryptography` package (Ed25519, ECDSA P-256, RSA-2048
with SHA-256).  The package under test shares nothing with it, so a
signature that dnssec-nv accepts was made by somebody else's reading of
the RFCs.

The chain it builds is

    .            DNSKEY 257 3 15   (Ed25519)   -- the trust anchor is its DS
    example.     DNSKEY 257 3 13   (ECDSA P-256), DS signed by the root key
    sub.example. DNSKEY 257 3 8    (RSA-2048),   DS signed by the example key

and the answers

    www.sub.example.    A   192.0.2.1
    a.b.sub.example.    TXT "wild"   (a wildcard expansion of *.sub.example.)
    mx.sub.example.     MX  10 Mail.SUB.example.   (signed with names lower case)

Run it with `python3 -I tests/make_chain_vectors.py`.  The Ed25519 and P-256
keys come from fixed seeds; the RSA key is generated afresh each run, and
so are the ECDSA and RSA signatures' randomness, so the output of one run
is what the test file holds, not what every run prints.  The output is a
Novo source fragment.
"""
import hashlib
import struct
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

INCEPTION = 1700000000   # 2023-11-14 22:13:20 UTC
EXPIRATION = 1702592000  # 30 days later


def name_wire(name, lower=True):
    if name == ".":
        return b"\x00"
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode()
        if lower:
            raw = raw.lower()
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def key_tag(rdata):
    ac = 0
    for i, b in enumerate(rdata):
        ac += b << 8 if i % 2 == 0 else b
    ac += (ac >> 16) & 0xFFFF
    return ac & 0xFFFF


def dnskey_rdata(flags, alg, pub):
    return struct.pack(">HBB", flags, 3, alg) + pub


def ds_rdata(owner, dk_rdata, alg):
    digest = hashlib.sha256(name_wire(owner) + dk_rdata).digest()
    return struct.pack(">HBB", key_tag(dk_rdata), alg, 2) + digest


def rr_wire(owner_wire, typ, ttl, rdata):
    return owner_wire + struct.pack(">HHIH", typ, 1, ttl, len(rdata)) + rdata


def rrsig(sign, signer, alg, tag, owner, typ, rdatas, ttl, labels):
    prefix = struct.pack(">HBBIIIH", typ, alg, labels, ttl, EXPIRATION, INCEPTION, tag) + name_wire(signer)
    # The wildcard owner is `*.` and the rightmost `labels` labels.
    signed_owner = owner
    if labels < labels_of(owner):
        parts = owner.rstrip(".").split(".")
        signed_owner = "*." + ".".join(parts[len(parts) - labels:]) + "."
    data = prefix
    for rd in sorted(set(rdatas)):
        data += rr_wire(name_wire(signed_owner), typ, ttl, rd)
    return prefix + sign(data)


def labels_of(name):
    if name == ".":
        return 0
    parts = name.rstrip(".").split(".")
    return len(parts) - (1 if parts[0] == "*" else 0)


def hexs(b):
    return b.hex()


# ── keys ────────────────────────────────────────────────────────────

ed = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
ed_pub = ed.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

p256 = ec.derive_private_key(0x1D4E92A1C0B6E3F5A7C9D1E3F507192B3D4F61728394A5B6C7D8E9FA0B1C2D3, ec.SECP256R1())
nums = p256.public_key().public_numbers()
p256_pub = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")

rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rn = rsa_key.public_key().public_numbers()
rsa_e = rn.e.to_bytes((rn.e.bit_length() + 7) // 8, "big")
rsa_n = rn.n.to_bytes(256, "big")
rsa_pub = bytes([len(rsa_e)]) + rsa_e + rsa_n


def sign_ed(data):
    return ed.sign(data)


def sign_p256(data):
    r, s = decode_dss_signature(p256.sign(data, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def sign_rsa(data):
    return rsa_key.sign(data, padding.PKCS1v15(), hashes.SHA256())


root_dk = dnskey_rdata(257, 15, ed_pub)
ex_dk = dnskey_rdata(257, 13, p256_pub)
sub_dk = dnskey_rdata(257, 8, rsa_pub)
tag_root, tag_ex, tag_sub = key_tag(root_dk), key_tag(ex_dk), key_tag(sub_dk)

root_anchor = ds_rdata(".", root_dk, 15)
ex_ds = ds_rdata("example.", ex_dk, 13)
sub_ds = ds_rdata("sub.example.", sub_dk, 8)

vectors = {}
vectors["root_dnskey"] = root_dk
vectors["root_anchor_ds"] = root_anchor
vectors["root_dnskey_sig"] = rrsig(sign_ed, ".", 15, tag_root, ".", 48, [root_dk], 3600, 0)
vectors["ex_ds"] = ex_ds
vectors["ex_ds_sig"] = rrsig(sign_ed, ".", 15, tag_root, "example.", 43, [ex_ds], 3600, 1)
# example.'s DNSKEY RRset with records a validator must leave out of the key
# set: a key without the zone bit, a revoked key, a DNSKEY whose protocol
# is 4, and one that is too short to parse; the whole RRset is signed by the
# example. key.
nz_dk = dnskey_rdata(1, 13, p256_pub)
rv_dk = dnskey_rdata(0x0181, 13, p256_pub)
p4_dk = struct.pack(">HBB", 257, 4, 13) + p256_pub
short_dk2 = bytes([1, 1])
vectors["ex_nz_dnskey"] = nz_dk
vectors["ex_rv_dnskey"] = rv_dk
vectors["ex_p4_dnskey"] = p4_dk
vectors["ex_short_dnskey"] = short_dk2
vectors["ex_dnskey_extra_sig"] = rrsig(sign_p256, "example.", 13, tag_ex, "example.", 48, [ex_dk, nz_dk, rv_dk, p4_dk, short_dk2], 3600, 1)
vectors["ex_dnskey"] = ex_dk
vectors["ex_dnskey_sig"] = rrsig(sign_p256, "example.", 13, tag_ex, "example.", 48, [ex_dk], 3600, 1)
vectors["sub_ds"] = sub_ds
vectors["sub_ds_sig"] = rrsig(sign_p256, "example.", 13, tag_ex, "sub.example.", 43, [sub_ds], 3600, 2)
# A DS of an algorithm this package does not verify, and one of a digest type
# it does not compute, each signed by the example. key; and one RRset that
# holds the good DS and the unsupported one.
bad_alg_ds = struct.pack(">HBB", tag_sub, 10, 2) + hashlib.sha256(name_wire("sub.example.") + sub_dk).digest()
gost_ds = struct.pack(">HBB", tag_sub, 8, 3) + hashlib.sha256(name_wire("sub.example.") + sub_dk).digest()
vectors["sub_ds_bad_alg"] = bad_alg_ds
vectors["sub_ds_bad_alg_sig"] = rrsig(sign_p256, "example.", 13, tag_ex, "sub.example.", 43, [bad_alg_ds], 3600, 2)
vectors["sub_ds_gost"] = gost_ds
vectors["sub_ds_gost_sig"] = rrsig(sign_p256, "example.", 13, tag_ex, "sub.example.", 43, [gost_ds], 3600, 2)
vectors["sub_ds_mixed_sig"] = rrsig(sign_p256, "example.", 13, tag_ex, "sub.example.", 43, [sub_ds, bad_alg_ds], 3600, 2)
# The DS RRset with a record too short to be a DS beside the good one.
junk_ds = bytes([0, 1, 2, 3])
vectors["sub_ds_junk"] = junk_ds
vectors["sub_ds_junk_sig"] = rrsig(sign_p256, "example.", 13, tag_ex, "sub.example.", 43, [sub_ds, junk_ds], 3600, 2)
# An A record at www.example. signed by the example. key but with the signer
# name "." (an ancestor, so the signature verifies): the signer is not the
# zone the chain ends at.
vectors["ex_www_a_root_signer_sig"] = rrsig(sign_p256, ".", 13, tag_ex, "www.example.", 1, [bytes([192, 0, 2, 1])], 300, 2)
vectors["sub_dnskey"] = sub_dk
vectors["sub_dnskey_sig"] = rrsig(sign_rsa, "sub.example.", 8, tag_sub, "sub.example.", 48, [sub_dk], 3600, 2)

www_a = bytes([192, 0, 2, 1])
vectors["www_a"] = www_a
vectors["www_a_sig"] = rrsig(sign_rsa, "sub.example.", 8, tag_sub, "www.sub.example.", 1, [www_a], 300, 3)

# A wildcard: *.sub.example. TXT "wild", signed with Labels 2 and answered
# for a.b.sub.example.
txt = bytes([4]) + b"wild"
vectors["wild_txt"] = txt
vectors["wild_txt_sig"] = rrsig(sign_rsa, "sub.example.", 8, tag_sub, "*.sub.example.", 16, [txt], 300, 2)

# An MX whose exchange is written with upper case letters in the answer and
# lower case in what was signed.
mx_signed = struct.pack(">H", 10) + name_wire("mail.sub.example.", lower=True)
mx_shown = struct.pack(">H", 10) + name_wire("Mail.SUB.example.", lower=False)
vectors["mx_shown"] = mx_shown
vectors["mx_sig"] = rrsig(sign_rsa, "sub.example.", 8, tag_sub, "mx.sub.example.", 15, [mx_signed], 300, 3)

# The RSA key with a short modulus is refused by rsa-nv; a 1024-bit key is
# signed here only to prove that.
short = rsa.generate_private_key(public_exponent=65537, key_size=1024)
sn = short.public_key().public_numbers()
se = sn.e.to_bytes((sn.e.bit_length() + 7) // 8, "big")
short_pub = bytes([len(se)]) + se + sn.n.to_bytes(128, "big")
short_dk = dnskey_rdata(257, 8, short_pub)
vectors["short_dnskey"] = short_dk
short_sig = struct.pack(">HBBIIIH", 1, 8, 3, 300, EXPIRATION, INCEPTION, key_tag(short_dk)) + name_wire("short.example.")
short_data = short_sig + rr_wire(name_wire("www.short.example."), 1, 300, www_a)
vectors["short_sig"] = short_sig + short.sign(short_data, padding.PKCS1v15(), hashes.SHA256())

print("// ── generated by tests/make_chain_vectors.py ──")
for k, v in vectors.items():
    print("fn v_%s() -> Str" % k)
    h = v.hex()
    chunks = [h[i:i + 64] for i in range(0, len(h), 64)]
    print("    " + " + ".join('"%s"' % c for c in chunks))
    print()
print("// tags: root %d, example %d, sub.example %d" % (tag_root, tag_ex, tag_sub), file=sys.stderr)
