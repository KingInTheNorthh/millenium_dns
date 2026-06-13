//! End-to-end DNSSEC chain validation.
//!
//! Validates a name **top-down** from the hard-coded root trust anchor:
//!
//! 1. Fetch the root DNSKEY set, confirm its self-signature, and confirm one of
//!    its keys matches the IANA root anchor (the only key trusted a priori).
//! 2. For each zone cut from the root down to the zone that signs the answer:
//!    fetch the child's DS (signed by the parent's keys we already trust),
//!    confirm a child DNSKEY hashes to that DS, and confirm the child DNSKEY
//!    set's self-signature. The child's keys then become the trusted set.
//! 3. Validate the answer RRset with the keys of its signing zone.
//!
//! Each step is reported as a [`ChainLink`]; the overall [`ChainStatus`] is the
//! weakest link. Because the cryptographic core only verifies RSA (see
//! [`crate::dnssec`]), a zone signed with ECDSA/EdDSA breaks the chain with
//! `Indeterminate` rather than a false `Secure`.

use crate::dnssec::{ValidationStatus, root_trust_anchor, validate_rrset, verify_ds};
use crate::error::Result;
use crate::protocol::{DnsPacket, DnsRecord, QueryType};
use crate::resolver::recursive_lookup;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainStatus {
    /// Validated all the way to the root anchor.
    Secure,
    /// A zone in the path is provably unsigned (no DS delegation).
    Insecure,
    /// A signature or DS that should have verified did not — possible forgery.
    Bogus,
    /// Could not conclude (unsupported algorithm or missing records).
    Indeterminate,
}

pub struct ChainLink {
    pub zone: String,
    pub detail: String,
    pub status: ChainStatus,
}

pub struct ChainReport {
    pub name: String,
    pub qtype: QueryType,
    pub signer: Option<String>,
    pub links: Vec<ChainLink>,
    pub overall: ChainStatus,
}

pub fn verify_chain(qname: &str, qtype: QueryType) -> Result<ChainReport> {
    let mut links = Vec::new();

    // --- The answer and the zone that signed it ----------------------------
    let answer = recursive_lookup(qname, qtype)?;
    let rrset = records_of_type(&answer, qtype, qname);
    let rrsig = rrsig_covering(&answer, qtype.to_num());
    let signer = match &rrsig {
        Some(DnsRecord::RRSIG { signer_name, .. }) => Some(normalize(signer_name)),
        _ => None,
    };

    // --- Step 1: anchor trust at the root ----------------------------------
    let (root_keys, root_sig) = match dnskey_set(".") {
        Ok(set) => set,
        Err(error) => {
            return Ok(report(qname, qtype, signer, links, ChainStatus::Indeterminate, error.to_string()));
        }
    };

    let anchor = root_trust_anchor();
    let anchored = root_keys.iter().any(|k| verify_ds(k, &anchor));
    let root_self = self_signature_status(&root_keys, &root_sig);

    let root_status = if !anchored {
        ChainStatus::Bogus
    } else {
        from_validation(root_self)
    };
    links.push(ChainLink {
        zone: ".".to_string(),
        detail: if anchored {
            format!("root KSK matches IANA anchor; DNSKEY self-sig {}", describe(root_self))
        } else {
            "root DNSKEY does NOT match the hard-coded anchor".to_string()
        },
        status: root_status,
    });
    if root_status != ChainStatus::Secure {
        return Ok(report(qname, qtype, signer, links, root_status, String::new()));
    }

    // --- Step 2: descend the delegation chain ------------------------------
    let mut trusted = root_keys;
    let signer_zone = signer.clone().unwrap_or_else(|| normalize(qname));

    for zone in chain_zones(&signer_zone) {
        let ds_packet = recursive_lookup(&zone, QueryType::DS)?;
        let ds_set = records_of_type(&ds_packet, QueryType::DS, &zone);

        if ds_set.is_empty() {
            // No DS published here. If this is the signing zone, the delegation
            // is unsigned (Insecure). Otherwise it simply isn't a zone cut, so
            // keep the current trusted keys and descend further.
            if zone == signer_zone {
                links.push(ChainLink {
                    zone: zone.clone(),
                    detail: "no DS at parent — unsigned (insecure) delegation".to_string(),
                    status: ChainStatus::Insecure,
                });
                return Ok(report(qname, qtype, signer, links, ChainStatus::Insecure, String::new()));
            }
            continue;
        }

        // The DS RRset must be signed by the parent zone's keys (our `trusted`).
        let ds_rrsig = rrsig_covering(&ds_packet, QueryType::DS.to_num());
        let ds_status = match ds_rrsig {
            Some(sig) => validate_rrset(&ds_set, &sig, &trusted),
            None => ValidationStatus::Indeterminate,
        };
        if ds_status != ValidationStatus::Secure {
            links.push(ChainLink {
                zone: zone.clone(),
                detail: format!("DS RRSIG {}", describe(ds_status)),
                status: from_validation(ds_status),
            });
            return Ok(report(qname, qtype, signer, links, from_validation(ds_status), String::new()));
        }

        // The child must publish a DNSKEY that hashes to the (now trusted) DS.
        let (child_keys, child_sig) = dnskey_set(&zone)?;
        let key_matches_ds = ds_set
            .iter()
            .any(|ds| child_keys.iter().any(|k| verify_ds(k, ds)));
        if !key_matches_ds {
            links.push(ChainLink {
                zone: zone.clone(),
                detail: "no child DNSKEY matches the trusted DS".to_string(),
                status: ChainStatus::Bogus,
            });
            return Ok(report(qname, qtype, signer, links, ChainStatus::Bogus, String::new()));
        }

        // And the child DNSKEY set must be self-signed.
        let self_status = self_signature_status(&child_keys, &child_sig);
        if self_status != ValidationStatus::Secure {
            links.push(ChainLink {
                zone: zone.clone(),
                detail: format!("DNSKEY self-sig {}", describe(self_status)),
                status: from_validation(self_status),
            });
            return Ok(report(qname, qtype, signer, links, from_validation(self_status), String::new()));
        }

        links.push(ChainLink {
            zone: zone.clone(),
            detail: "DS validated, DNSKEY matches DS and is self-signed".to_string(),
            status: ChainStatus::Secure,
        });
        trusted = child_keys;
    }

    // --- Step 3: validate the actual answer --------------------------------
    let answer_status = match &rrsig {
        Some(sig) if !rrset.is_empty() => validate_rrset(&rrset, sig, &trusted),
        _ => ValidationStatus::Indeterminate,
    };
    let overall = from_validation(answer_status);
    links.push(ChainLink {
        zone: signer_zone,
        detail: format!("answer {:?} RRSIG {}", qtype, describe(answer_status)),
        status: overall,
    });

    Ok(report(qname, qtype, signer, links, overall, String::new()))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn report(
    name: &str,
    qtype: QueryType,
    signer: Option<String>,
    mut links: Vec<ChainLink>,
    overall: ChainStatus,
    error_detail: String,
) -> ChainReport {
    if !error_detail.is_empty() {
        links.push(ChainLink {
            zone: ".".to_string(),
            detail: error_detail,
            status: ChainStatus::Indeterminate,
        });
    }
    ChainReport {
        name: name.to_string(),
        qtype,
        signer,
        links,
        overall,
    }
}

/// Fetch a zone's DNSKEY RRset together with the RRSIG that covers it.
fn dnskey_set(zone: &str) -> Result<(Vec<DnsRecord>, Option<DnsRecord>)> {
    let packet = recursive_lookup(zone, QueryType::DNSKEY)?;
    let keys = records_of_type(&packet, QueryType::DNSKEY, zone);
    let rrsig = rrsig_covering(&packet, QueryType::DNSKEY.to_num());
    Ok((keys, rrsig))
}

/// Validate a DNSKEY RRset against its own self-signature.
fn self_signature_status(keys: &[DnsRecord], rrsig: &Option<DnsRecord>) -> ValidationStatus {
    match rrsig {
        Some(sig) if !keys.is_empty() => validate_rrset(keys, sig, keys),
        _ => ValidationStatus::Indeterminate,
    }
}

/// The zone cuts from just below the root down to (and including) `signer`.
/// e.g. `verisignlabs.com` -> `["com", "verisignlabs.com"]`.
fn chain_zones(signer: &str) -> Vec<String> {
    let signer = normalize(signer);
    if signer.is_empty() {
        return Vec::new();
    }
    let labels: Vec<&str> = signer.split('.').collect();
    (0..labels.len()).rev().map(|i| labels[i..].join(".")).collect()
}

fn from_validation(status: ValidationStatus) -> ChainStatus {
    match status {
        ValidationStatus::Secure => ChainStatus::Secure,
        ValidationStatus::Bogus => ChainStatus::Bogus,
        ValidationStatus::Indeterminate => ChainStatus::Indeterminate,
    }
}

fn describe(status: ValidationStatus) -> &'static str {
    match status {
        ValidationStatus::Secure => "secure",
        ValidationStatus::Bogus => "BOGUS",
        ValidationStatus::Indeterminate => "indeterminate",
    }
}

fn records_of_type(packet: &DnsPacket, qtype: QueryType, name: &str) -> Vec<DnsRecord> {
    let name = normalize(name);
    packet
        .answers
        .iter()
        .chain(packet.authorities.iter())
        .filter(|r| record_qtype(r) == qtype)
        .filter(|r| r.domain().map(normalize).as_deref() == Some(name.as_str()))
        .cloned()
        .collect()
}

fn rrsig_covering(packet: &DnsPacket, type_covered: u16) -> Option<DnsRecord> {
    packet
        .answers
        .iter()
        .chain(packet.authorities.iter())
        .find(|r| matches!(r, DnsRecord::RRSIG { type_covered: t, .. } if *t == type_covered))
        .cloned()
}

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_zones_are_root_to_signer() {
        assert_eq!(chain_zones("verisignlabs.com"), vec!["com", "verisignlabs.com"]);
        assert_eq!(
            chain_zones("a.b.example.org"),
            vec!["org", "example.org", "b.example.org", "a.b.example.org"]
        );
        assert!(chain_zones(".").is_empty());
    }
}
