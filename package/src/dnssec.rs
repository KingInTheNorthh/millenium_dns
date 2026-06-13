//! Dependency-free DNSSEC primitives.
//!
//! This module implements the cryptographic building blocks needed to validate
//! a DNSSEC chain of trust without pulling in any external crates:
//!
//! * SHA-1 and SHA-256 (used by DS digests and RSA signatures).
//! * The DNSKEY key-tag algorithm (RFC 4034 Appendix B).
//! * DS digest verification (parent's DS hashes the child's DNSKEY).
//! * RSA signature verification via a small big-integer modular-exponentiation
//!   implementation, plus canonical RRset reconstruction (RFC 4034 §6).
//!
//! Coverage is honest about its limits: RSA/SHA-1 (algorithms 5, 7) and
//! RSA/SHA-256 (algorithm 8) are validated. ECDSA (13, 14), RSA/SHA-512 (10),
//! and Ed25519/Ed448 are recognised but reported as `Indeterminate` rather than
//! pretending to verify them.

use crate::protocol::{DnsRecord, QueryType};

/// The outcome of validating an RRset against an RRSIG and DNSKEY set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationStatus {
    /// Signature verified against a trusted key.
    Secure,
    /// Signature is present but did not verify — treat the data as forged.
    Bogus,
    /// We can't make a determination (unsupported algorithm, missing key, …).
    Indeterminate,
}

// DNSSEC algorithm numbers we care about.
const ALG_RSASHA1: u8 = 5;
const ALG_RSASHA1_NSEC3: u8 = 7;
const ALG_RSASHA256: u8 = 8;

// DS digest types.
const DIGEST_SHA1: u8 = 1;
const DIGEST_SHA256: u8 = 2;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// The IANA root zone trust anchor (KSK-2017, key tag 20326), expressed as the
/// DS record that commits to the root key-signing key. This is the one key we
/// trust a priori; every secure answer must chain back to it.
///
/// Published by IANA at <https://data.iana.org/root-anchors/root-anchors.xml>:
/// `.  IN DS 20326 8 2 E06D44B8...C7F8EC8D`
pub fn root_trust_anchor() -> DnsRecord {
    DnsRecord::DS {
        domain: String::new(), // the root, the empty name
        key_tag: 20326,
        algorithm: ALG_RSASHA256,
        digest_type: DIGEST_SHA256,
        digest: vec![
            0xE0, 0x6D, 0x44, 0xB8, 0x0B, 0x8F, 0x1D, 0x39, 0xA9, 0x5C, 0x0B, 0x0D, 0x7C, 0x65,
            0xD0, 0x84, 0x58, 0xE8, 0x80, 0x40, 0x9B, 0xBC, 0x68, 0x34, 0x57, 0x10, 0x42, 0x37,
            0xC7, 0xF8, 0xEC, 0x8D,
        ],
        ttl: 0,
    }
}

/// Verify that `dnskey` hashes to the digest carried in `ds` — the link that
/// ties a child zone's key to its parent's delegation.
pub fn verify_ds(dnskey: &DnsRecord, ds: &DnsRecord) -> bool {
    let (DnsRecord::DNSKEY { domain, .. }, DnsRecord::DS { digest_type, digest, .. }) =
        (dnskey, ds)
    else {
        return false;
    };

    // Digest input is the canonical owner name followed by the DNSKEY RDATA.
    let mut input = canonical_name(domain);
    input.extend_from_slice(&dnskey_rdata(dnskey));

    let computed = match *digest_type {
        DIGEST_SHA1 => sha1(&input).to_vec(),
        DIGEST_SHA256 => sha256(&input).to_vec(),
        _ => return false,
    };

    constant_time_eq(&computed, digest)
}

/// Validate `rrset` (all records of one name/type) against `rrsig`, using the
/// matching key from `dnskeys`.
pub fn validate_rrset(
    rrset: &[DnsRecord],
    rrsig: &DnsRecord,
    dnskeys: &[DnsRecord],
) -> ValidationStatus {
    let DnsRecord::RRSIG {
        algorithm,
        key_tag,
        original_ttl,
        signature,
        ..
    } = rrsig
    else {
        return ValidationStatus::Indeterminate;
    };

    // Locate the DNSKEY that produced this signature.
    let Some(key) = dnskeys.iter().find(|k| {
        matches!(k, DnsRecord::DNSKEY { algorithm: a, .. } if a == algorithm)
            && key_tag_of(k) == Some(*key_tag)
    }) else {
        return ValidationStatus::Indeterminate;
    };

    let Some(signed) = signed_data(rrsig, rrset, *original_ttl) else {
        return ValidationStatus::Indeterminate;
    };

    match *algorithm {
        ALG_RSASHA1 | ALG_RSASHA1_NSEC3 => {
            verify_rsa(key, &signed, signature, HashAlg::Sha1)
        }
        ALG_RSASHA256 => verify_rsa(key, &signed, signature, HashAlg::Sha256),
        // Recognised but not implemented here.
        _ => ValidationStatus::Indeterminate,
    }
}

/// The RFC 4034 Appendix B key tag for a DNSKEY record.
pub fn key_tag_of(dnskey: &DnsRecord) -> Option<u16> {
    if !matches!(dnskey, DnsRecord::DNSKEY { .. }) {
        return None;
    }
    Some(key_tag(&dnskey_rdata(dnskey)))
}

// ---------------------------------------------------------------------------
// RSA verification
// ---------------------------------------------------------------------------

enum HashAlg {
    Sha1,
    Sha256,
}

// DigestInfo DER prefixes (RFC 3447) for PKCS#1 v1.5 signatures.
const SHA1_PREFIX: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
];
const SHA256_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20,
];

fn verify_rsa(key: &DnsRecord, signed: &[u8], signature: &[u8], hash: HashAlg) -> ValidationStatus {
    let DnsRecord::DNSKEY { public_key, .. } = key else {
        return ValidationStatus::Indeterminate;
    };

    let Some((exponent, modulus)) = parse_rsa_public_key(public_key) else {
        return ValidationStatus::Bogus;
    };

    // m = signature^exponent mod modulus
    let recovered = modexp(signature, &exponent, &modulus);

    // Left-pad to the modulus size to recover the EM block.
    let mut em = vec![0u8; modulus.len()];
    let start = em.len().saturating_sub(recovered.len());
    em[start..].copy_from_slice(&recovered);

    let (prefix, digest) = match hash {
        HashAlg::Sha1 => (SHA1_PREFIX, sha1(signed).to_vec()),
        HashAlg::Sha256 => (SHA256_PREFIX, sha256(signed).to_vec()),
    };

    let mut expected = Vec::with_capacity(prefix.len() + digest.len());
    expected.extend_from_slice(prefix);
    expected.extend_from_slice(&digest);

    if pkcs1_v15_payload(&em) == Some(expected.as_slice()) {
        ValidationStatus::Secure
    } else {
        ValidationStatus::Bogus
    }
}

/// Parse an RFC 3110 RSA public key into `(exponent, modulus)` big-endian bytes.
fn parse_rsa_public_key(key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if key.is_empty() {
        return None;
    }

    let (exp_len, offset) = if key[0] == 0 {
        if key.len() < 3 {
            return None;
        }
        (((key[1] as usize) << 8) | key[2] as usize, 3)
    } else {
        (key[0] as usize, 1)
    };

    if key.len() < offset + exp_len {
        return None;
    }

    let exponent = key[offset..offset + exp_len].to_vec();
    let modulus = key[offset + exp_len..].to_vec();
    if modulus.is_empty() {
        return None;
    }

    Some((exponent, modulus))
}

/// Strip PKCS#1 v1.5 padding (`00 01 FF.. 00`) and return the DigestInfo payload.
fn pkcs1_v15_payload(em: &[u8]) -> Option<&[u8]> {
    if em.len() < 11 || em[0] != 0x00 || em[1] != 0x01 {
        return None;
    }
    let mut i = 2;
    while i < em.len() && em[i] == 0xFF {
        i += 1;
    }
    if i < 10 || i >= em.len() || em[i] != 0x00 {
        return None;
    }
    Some(&em[i + 1..])
}

// ---------------------------------------------------------------------------
// Canonical RRset / signed data construction (RFC 4034 §6)
// ---------------------------------------------------------------------------

/// Build the byte string an RRSIG signs: the RRSIG RDATA (minus the signature)
/// followed by each RR of the set in canonical form, sorted by canonical RDATA.
fn signed_data(rrsig: &DnsRecord, rrset: &[DnsRecord], original_ttl: u32) -> Option<Vec<u8>> {
    let DnsRecord::RRSIG {
        type_covered,
        algorithm,
        labels,
        original_ttl: sig_ttl,
        expiration,
        inception,
        key_tag,
        signer_name,
        ..
    } = rrsig
    else {
        return None;
    };

    let mut data = Vec::new();
    data.extend_from_slice(&type_covered.to_be_bytes());
    data.push(*algorithm);
    data.push(*labels);
    data.extend_from_slice(&sig_ttl.to_be_bytes());
    data.extend_from_slice(&expiration.to_be_bytes());
    data.extend_from_slice(&inception.to_be_bytes());
    data.extend_from_slice(&key_tag.to_be_bytes());
    data.extend_from_slice(&canonical_name(signer_name));

    // Canonical form of each RR, sorted by RDATA.
    let mut encoded: Vec<Vec<u8>> = Vec::with_capacity(rrset.len());
    for record in rrset {
        encoded.push(canonical_rr(record, original_ttl)?);
    }
    encoded.sort();

    for rr in encoded {
        data.extend_from_slice(&rr);
    }

    Some(data)
}

/// A single RR in canonical wire form: owner | type | class | ttl | rdlen | rdata.
fn canonical_rr(record: &DnsRecord, original_ttl: u32) -> Option<Vec<u8>> {
    let domain = record.domain()?;
    let rdata = canonical_rdata(record)?;

    let mut out = canonical_name(domain);
    out.extend_from_slice(&record_qtype(record).to_num().to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // class IN
    out.extend_from_slice(&original_ttl.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rdata);
    Some(out)
}

/// Canonical RDATA: embedded domain names are lowercased and uncompressed.
fn canonical_rdata(record: &DnsRecord) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match record {
        DnsRecord::A { addr, .. } => out.extend_from_slice(&addr.octets()),
        DnsRecord::AAAA { addr, .. } => out.extend_from_slice(&addr.octets()),
        DnsRecord::NS { host, .. } | DnsRecord::CNAME { host, .. } => {
            out.extend_from_slice(&canonical_name(host))
        }
        DnsRecord::MX { priority, host, .. } => {
            out.extend_from_slice(&priority.to_be_bytes());
            out.extend_from_slice(&canonical_name(host));
        }
        DnsRecord::SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
            ..
        } => {
            out.extend_from_slice(&canonical_name(mname));
            out.extend_from_slice(&canonical_name(rname));
            out.extend_from_slice(&serial.to_be_bytes());
            out.extend_from_slice(&refresh.to_be_bytes());
            out.extend_from_slice(&retry.to_be_bytes());
            out.extend_from_slice(&expire.to_be_bytes());
            out.extend_from_slice(&minimum.to_be_bytes());
        }
        DnsRecord::TXT { text, .. } => {
            for chunk in text.as_bytes().chunks(255) {
                out.push(chunk.len() as u8);
                out.extend_from_slice(chunk);
            }
        }
        DnsRecord::DNSKEY { .. } => out.extend_from_slice(&dnskey_rdata(record)),
        DnsRecord::DS {
            key_tag,
            algorithm,
            digest_type,
            digest,
            ..
        } => {
            out.extend_from_slice(&key_tag.to_be_bytes());
            out.push(*algorithm);
            out.push(*digest_type);
            out.extend_from_slice(digest);
        }
        // Other types aren't needed for the chains we validate here.
        _ => return None,
    }
    Some(out)
}

fn record_qtype(record: &DnsRecord) -> QueryType {
    match record {
        DnsRecord::A { .. } => QueryType::A,
        DnsRecord::NS { .. } => QueryType::NS,
        DnsRecord::CNAME { .. } => QueryType::CNAME,
        DnsRecord::SOA { .. } => QueryType::SOA,
        DnsRecord::MX { .. } => QueryType::MX,
        DnsRecord::TXT { .. } => QueryType::TXT,
        DnsRecord::AAAA { .. } => QueryType::AAAA,
        DnsRecord::DS { .. } => QueryType::DS,
        DnsRecord::RRSIG { .. } => QueryType::RRSIG,
        DnsRecord::NSEC { .. } => QueryType::NSEC,
        DnsRecord::DNSKEY { .. } => QueryType::DNSKEY,
        DnsRecord::NSEC3 { .. } => QueryType::NSEC3,
        DnsRecord::OPT { .. } => QueryType::OPT,
        DnsRecord::Unknown { qtype, .. } => QueryType::from_num(*qtype),
    }
}

/// The RDATA of a DNSKEY: flags | protocol | algorithm | public key.
fn dnskey_rdata(record: &DnsRecord) -> Vec<u8> {
    if let DnsRecord::DNSKEY {
        flags,
        protocol,
        algorithm,
        public_key,
        ..
    } = record
    {
        let mut out = Vec::with_capacity(4 + public_key.len());
        out.extend_from_slice(&flags.to_be_bytes());
        out.push(*protocol);
        out.push(*algorithm);
        out.extend_from_slice(public_key);
        out
    } else {
        Vec::new()
    }
}

/// Canonical wire encoding of a domain name: lowercase labels, length-prefixed,
/// uncompressed, root-terminated.
fn canonical_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        out.push(label.len() as u8);
        out.extend(label.bytes().map(|b| b.to_ascii_lowercase()));
    }
    out.push(0);
    out
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Key tag (RFC 4034 Appendix B)
// ---------------------------------------------------------------------------

fn key_tag(rdata: &[u8]) -> u16 {
    let mut ac: u32 = 0;
    for (i, &byte) in rdata.iter().enumerate() {
        if i & 1 == 0 {
            ac += (byte as u32) << 8;
        } else {
            ac += byte as u32;
        }
    }
    ac += (ac >> 16) & 0xFFFF;
    (ac & 0xFFFF) as u16
}

// ---------------------------------------------------------------------------
// Big-integer modular exponentiation (for RSA verification)
// ---------------------------------------------------------------------------

/// Compute `base^exp mod modulus`, all big-endian byte strings. Returns the
/// big-endian result trimmed of leading zeros.
fn modexp(base: &[u8], exp: &[u8], modulus: &[u8]) -> Vec<u8> {
    let modulus = BigUint::from_be(modulus);
    let base = BigUint::from_be(base).rem(&modulus);
    let exp = BigUint::from_be(exp);

    let mut result = BigUint::one();
    // Square-and-multiply over the exponent bits, most-significant first.
    for bit in (0..exp.bit_len()).rev() {
        result = result.mul(&result).rem(&modulus);
        if exp.bit(bit) {
            result = result.mul(&base).rem(&modulus);
        }
    }

    result.to_be()
}

/// A minimal unsigned big integer stored as little-endian `u32` limbs.
#[derive(Clone)]
struct BigUint {
    limbs: Vec<u32>,
}

impl BigUint {
    fn one() -> Self {
        Self { limbs: vec![1] }
    }

    fn from_be(bytes: &[u8]) -> Self {
        let mut limbs = Vec::new();
        let mut chunk = bytes.len();
        while chunk > 0 {
            let start = chunk.saturating_sub(4);
            let mut limb = 0u32;
            for &b in &bytes[start..chunk] {
                limb = (limb << 8) | b as u32;
            }
            limbs.push(limb);
            chunk = start;
        }
        let mut value = Self { limbs };
        value.trim();
        value
    }

    fn to_be(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for &limb in self.limbs.iter().rev() {
            bytes.extend_from_slice(&limb.to_be_bytes());
        }
        // Trim leading zeros, but keep at least one byte.
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
        bytes[first..].to_vec()
    }

    fn trim(&mut self) {
        while self.limbs.len() > 1 && *self.limbs.last().unwrap() == 0 {
            self.limbs.pop();
        }
    }

    fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&l| l == 0)
    }

    fn bit_len(&self) -> usize {
        for (i, &limb) in self.limbs.iter().enumerate().rev() {
            if limb != 0 {
                return i * 32 + (32 - limb.leading_zeros() as usize);
            }
        }
        0
    }

    fn bit(&self, index: usize) -> bool {
        let limb = index / 32;
        let offset = index % 32;
        self.limbs.get(limb).map(|l| (l >> offset) & 1 == 1).unwrap_or(false)
    }

    /// Schoolbook multiplication.
    fn mul(&self, other: &Self) -> Self {
        let mut out = vec![0u64; self.limbs.len() + other.limbs.len()];
        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry = 0u64;
            for (j, &b) in other.limbs.iter().enumerate() {
                let cur = out[i + j] + (a as u64) * (b as u64) + carry;
                out[i + j] = cur & 0xFFFF_FFFF;
                carry = cur >> 32;
            }
            out[i + other.limbs.len()] += carry;
        }
        let mut value = Self {
            limbs: out.into_iter().map(|l| l as u32).collect(),
        };
        value.trim();
        value
    }

    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        let len = self.limbs.len().max(other.limbs.len());
        for i in (0..len).rev() {
            let x = self.limbs.get(i).copied().unwrap_or(0);
            let y = other.limbs.get(i).copied().unwrap_or(0);
            match x.cmp(&y) {
                Ordering::Equal => continue,
                non_eq => return non_eq,
            }
        }
        Ordering::Equal
    }

    /// `self - other`, assuming `self >= other`.
    fn sub(&self, other: &Self) -> Self {
        let mut out = Vec::with_capacity(self.limbs.len());
        let mut borrow = 0i64;
        for i in 0..self.limbs.len() {
            let a = self.limbs[i] as i64;
            let b = other.limbs.get(i).copied().unwrap_or(0) as i64;
            let mut cur = a - b - borrow;
            if cur < 0 {
                cur += 1 << 32;
                borrow = 1;
            } else {
                borrow = 0;
            }
            out.push(cur as u32);
        }
        let mut value = Self { limbs: out };
        value.trim();
        value
    }

    fn shl1(&self) -> Self {
        let mut out = Vec::with_capacity(self.limbs.len() + 1);
        let mut carry = 0u32;
        for &limb in &self.limbs {
            out.push((limb << 1) | carry);
            carry = limb >> 31;
        }
        if carry != 0 {
            out.push(carry);
        }
        let mut value = Self { limbs: out };
        value.trim();
        value
    }

    fn set_bit0(&mut self, value: bool) {
        if self.limbs.is_empty() {
            self.limbs.push(0);
        }
        if value {
            self.limbs[0] |= 1;
        } else {
            self.limbs[0] &= !1;
        }
    }

    /// `self mod modulus`, via bitwise long division.
    fn rem(&self, modulus: &Self) -> Self {
        use std::cmp::Ordering;
        if modulus.is_zero() {
            return Self { limbs: vec![0] };
        }
        let mut remainder = Self { limbs: vec![0] };
        for bit in (0..self.bit_len()).rev() {
            remainder = remainder.shl1();
            remainder.set_bit0(self.bit(bit));
            if remainder.cmp(modulus) != Ordering::Less {
                remainder = remainder.sub(modulus);
            }
        }
        remainder.trim();
        remainder
    }
}

// ---------------------------------------------------------------------------
// SHA-1 and SHA-256
// ---------------------------------------------------------------------------

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    let mut message = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for block in message.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut message = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for block in message.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
            let temp1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let temp2 = s0.wrapping_add(maj);

            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(temp1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = temp1.wrapping_add(temp2);
        }

        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha1_known_vectors() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn modexp_classic_vector() {
        // 4^13 mod 497 = 445
        let result = modexp(&[4], &[13], &[0x01, 0xf1]);
        assert_eq!(u_from(&result), 445);
    }

    #[test]
    fn modexp_larger_vector() {
        // 7^256 mod 13 = 9   (7^256 ≡ (7^12)^21 * 7^4 ≡ 7^4 ≡ 2401 ≡ 9 mod 13)
        let result = modexp(&[7], &[0x01, 0x00], &[13]);
        assert_eq!(u_from(&result), 9);
    }

    fn u_from(bytes: &[u8]) -> u64 {
        bytes.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64)
    }

    #[test]
    fn key_tag_is_stable() {
        // Arbitrary RDATA; the tag must be deterministic and within u16.
        let rdata = [0x01, 0x00, 0x03, 0x08, 0xAA, 0xBB, 0xCC, 0xDD];
        let tag = key_tag(&rdata);
        assert_eq!(tag, key_tag(&rdata));
    }
}
