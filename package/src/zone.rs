//! Authoritative zone hosting.
//!
//! Loads a pragmatic subset of the RFC 1035 master-file format and answers
//! queries for names the server owns, setting the AA (authoritative answer)
//! flag. Anything outside a hosted zone is left to recursive resolution.

use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use crate::error::{Result, dns_error};
use crate::protocol::{DnsQuestion, DnsRecord, QueryType, ResultCode};

/// The records a zone lookup produced, plus the result code to report.
pub struct ZoneAnswer {
    pub rescode: ResultCode,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
}

/// A single authoritative zone: an origin, its SOA, and all of its records.
struct Zone {
    origin: String,
    soa: DnsRecord,
    records: Vec<DnsRecord>,
}

/// A collection of hosted zones.
#[derive(Default)]
pub struct ZoneStore {
    zones: Vec<Zone>,
}

impl ZoneStore {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Load each path as a zone file. Each file must declare its origin via
    /// `$ORIGIN` (or carry a `@`-rooted SOA after an `$ORIGIN`).
    pub fn load_files<P: AsRef<Path>>(paths: &[P]) -> Result<Self> {
        let mut zones = Vec::new();
        for path in paths {
            let text = fs::read_to_string(path)?;
            zones.push(parse_zone(&text)?);
        }
        Ok(Self { zones })
    }

    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    pub fn origins(&self) -> Vec<&str> {
        self.zones.iter().map(|z| z.origin.as_str()).collect()
    }

    /// Answer a question authoritatively, or `None` if no hosted zone owns the
    /// queried name.
    pub fn lookup(&self, question: &DnsQuestion) -> Option<ZoneAnswer> {
        let name = normalize(&question.name);
        let zone = self.zone_for(&name)?;

        // Records owned at exactly this name.
        let at_name: Vec<&DnsRecord> = zone
            .records
            .iter()
            .filter(|r| r.domain().map(normalize).as_deref() == Some(name.as_str()))
            .collect();

        // Exact type match.
        let mut answers: Vec<DnsRecord> = at_name
            .iter()
            .filter(|r| record_qtype(r) == question.qtype)
            .map(|r| (*r).clone())
            .collect();

        if !answers.is_empty() {
            return Some(ZoneAnswer {
                rescode: ResultCode::NoError,
                answers,
                authorities: Vec::new(),
            });
        }

        // A CNAME at the name answers any type (the resolver/client follows it).
        if question.qtype != QueryType::CNAME {
            for record in &at_name {
                if let DnsRecord::CNAME { .. } = record {
                    answers.push((*record).clone());
                }
            }
            if !answers.is_empty() {
                return Some(ZoneAnswer {
                    rescode: ResultCode::NoError,
                    answers,
                    authorities: Vec::new(),
                });
            }
        }

        // The name exists but has no record of this type: NODATA.
        if !at_name.is_empty() {
            return Some(ZoneAnswer {
                rescode: ResultCode::NoError,
                answers: Vec::new(),
                authorities: vec![zone.soa.clone()],
            });
        }

        // The name is within our zone but doesn't exist at all: NXDOMAIN.
        Some(ZoneAnswer {
            rescode: ResultCode::NxDomain,
            answers: Vec::new(),
            authorities: vec![zone.soa.clone()],
        })
    }

    /// The hosted zone whose origin is the longest suffix of `name`.
    fn zone_for(&self, name: &str) -> Option<&Zone> {
        self.zones
            .iter()
            .filter(|zone| {
                let origin = &zone.origin;
                name == origin || name.ends_with(&format!(".{origin}"))
            })
            .max_by_key(|zone| zone.origin.len())
    }
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

/// Parse a zone-file into a [`Zone`]. Supports `$ORIGIN`, `$TTL`, `@`, relative
/// and absolute owner names, `;` comments, and `( ... )` line continuations.
fn parse_zone(text: &str) -> Result<Zone> {
    let mut origin = String::new();
    let mut default_ttl: u32 = 3600;
    let mut last_name = String::new();
    let mut records: Vec<DnsRecord> = Vec::new();
    let mut soa: Option<DnsRecord> = None;

    for line in logical_lines(text) {
        let mut tokens = line.split_whitespace().peekable();
        let Some(first) = tokens.peek().copied() else {
            continue;
        };

        if first.eq_ignore_ascii_case("$ORIGIN") {
            tokens.next();
            origin = normalize(tokens.next().ok_or_else(|| dns_error("$ORIGIN missing value"))?);
            continue;
        }
        if first.eq_ignore_ascii_case("$TTL") {
            tokens.next();
            default_ttl = tokens
                .next()
                .ok_or_else(|| dns_error("$TTL missing value"))?
                .parse()
                .map_err(|_| dns_error("invalid $TTL"))?;
            continue;
        }

        // Owner name: present unless the line begins with whitespace, in which
        // case it inherits the previous owner.
        let owner = if line.starts_with(char::is_whitespace) {
            last_name.clone()
        } else {
            let raw = tokens.next().unwrap();
            last_name = resolve_name(raw, &origin)?;
            last_name.clone()
        };

        // Optional TTL, optional class (IN), then the type.
        let mut ttl = default_ttl;
        let mut next = tokens.next().ok_or_else(|| dns_error("record missing type"))?;
        if let Ok(value) = next.parse::<u32>() {
            ttl = value;
            next = tokens.next().ok_or_else(|| dns_error("record missing type"))?;
        }
        if next.eq_ignore_ascii_case("IN") {
            next = tokens.next().ok_or_else(|| dns_error("record missing type"))?;
        }

        let rtype = next.to_ascii_uppercase();
        let rest: Vec<&str> = tokens.collect();
        let record = build_record(&owner, ttl, &rtype, &rest, &origin)?;

        if let DnsRecord::SOA { .. } = &record {
            soa = Some(record.clone());
        }
        records.push(record);
    }

    if origin.is_empty() {
        return Err(dns_error("zone file has no $ORIGIN"));
    }
    let soa = soa.ok_or_else(|| dns_error("zone file has no SOA record"))?;

    Ok(Zone {
        origin,
        soa,
        records,
    })
}

/// Collapse `;` comments and `( ... )` continuations into one logical line each.
fn logical_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;

    for raw in text.lines() {
        // Strip comments (we don't support ';' inside quoted strings here).
        let line = match raw.find(';') {
            Some(idx) => &raw[..idx],
            None => raw,
        };

        for ch in line.chars() {
            match ch {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
        }

        let cleaned = line.replace(['(', ')'], " ");
        if current.is_empty() {
            current.push_str(&cleaned);
        } else {
            current.push(' ');
            current.push_str(cleaned.trim());
        }

        if depth <= 0 {
            if !current.trim().is_empty() {
                lines.push(current.clone());
            }
            current.clear();
            depth = 0;
        }
    }

    if !current.trim().is_empty() {
        lines.push(current);
    }
    lines
}

/// Resolve a (possibly relative or `@`) owner/target name against the origin.
fn resolve_name(name: &str, origin: &str) -> Result<String> {
    if name == "@" {
        if origin.is_empty() {
            return Err(dns_error("'@' used before $ORIGIN"));
        }
        return Ok(origin.to_string());
    }
    if let Some(stripped) = name.strip_suffix('.') {
        return Ok(normalize(stripped));
    }
    if origin.is_empty() {
        return Err(dns_error("relative name used before $ORIGIN"));
    }
    Ok(format!("{}.{}", normalize(name), origin))
}

fn build_record(
    owner: &str,
    ttl: u32,
    rtype: &str,
    rest: &[&str],
    origin: &str,
) -> Result<DnsRecord> {
    let domain = owner.to_string();

    match rtype {
        "A" => {
            let addr: Ipv4Addr = field(rest, 0)?.parse().map_err(|_| dns_error("bad A address"))?;
            Ok(DnsRecord::A { domain, addr, ttl })
        }
        "AAAA" => {
            let addr: Ipv6Addr = field(rest, 0)?
                .parse()
                .map_err(|_| dns_error("bad AAAA address"))?;
            Ok(DnsRecord::AAAA { domain, addr, ttl })
        }
        "NS" => Ok(DnsRecord::NS {
            domain,
            host: resolve_name(field(rest, 0)?, origin)?,
            ttl,
        }),
        "CNAME" => Ok(DnsRecord::CNAME {
            domain,
            host: resolve_name(field(rest, 0)?, origin)?,
            ttl,
        }),
        "MX" => Ok(DnsRecord::MX {
            domain,
            priority: field(rest, 0)?
                .parse()
                .map_err(|_| dns_error("bad MX priority"))?,
            host: resolve_name(field(rest, 1)?, origin)?,
            ttl,
        }),
        "TXT" => {
            let text = rest.join(" ");
            let text = text.trim_matches('"').to_string();
            Ok(DnsRecord::TXT { domain, text, ttl })
        }
        "SOA" => {
            let mname = resolve_name(field(rest, 0)?, origin)?;
            let rname = resolve_name(field(rest, 1)?, origin)?;
            Ok(DnsRecord::SOA {
                domain,
                mname,
                rname,
                serial: field(rest, 2)?.parse().map_err(|_| dns_error("bad SOA serial"))?,
                refresh: field(rest, 3)?.parse().map_err(|_| dns_error("bad SOA refresh"))?,
                retry: field(rest, 4)?.parse().map_err(|_| dns_error("bad SOA retry"))?,
                expire: field(rest, 5)?.parse().map_err(|_| dns_error("bad SOA expire"))?,
                minimum: field(rest, 6)?.parse().map_err(|_| dns_error("bad SOA minimum"))?,
                ttl,
            })
        }
        other => Err(dns_error(format!("unsupported zone record type: {other}"))),
    }
}

fn field<'a>(rest: &'a [&'a str], idx: usize) -> Result<&'a str> {
    rest.get(idx)
        .copied()
        .ok_or_else(|| dns_error("zone record missing a field"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZONE: &str = "\
$ORIGIN example.com.
$TTL 3600
@   IN SOA ns1.example.com. admin.example.com. (
        2024010101 ; serial
        7200       ; refresh
        3600       ; retry
        1209600    ; expire
        3600 )     ; minimum
@           IN NS    ns1.example.com.
@           IN A     93.184.216.34
www         IN A     93.184.216.34
mail        IN AAAA  ::1
@           IN MX    10 mail.example.com.
ftp         IN CNAME www.example.com.
";

    fn store() -> ZoneStore {
        ZoneStore {
            zones: vec![parse_zone(ZONE).unwrap()],
        }
    }

    #[test]
    fn answers_apex_a() {
        let answer = store()
            .lookup(&DnsQuestion::new("example.com".into(), QueryType::A))
            .unwrap();
        assert_eq!(answer.rescode, ResultCode::NoError);
        assert_eq!(answer.answers.len(), 1);
    }

    #[test]
    fn answers_subdomain_a() {
        let answer = store()
            .lookup(&DnsQuestion::new("www.example.com.".into(), QueryType::A))
            .unwrap();
        assert_eq!(answer.answers.len(), 1);
    }

    #[test]
    fn cname_answers_a_query() {
        let answer = store()
            .lookup(&DnsQuestion::new("ftp.example.com".into(), QueryType::A))
            .unwrap();
        assert!(matches!(answer.answers[0], DnsRecord::CNAME { .. }));
    }

    #[test]
    fn missing_name_is_nxdomain() {
        let answer = store()
            .lookup(&DnsQuestion::new("nope.example.com".into(), QueryType::A))
            .unwrap();
        assert_eq!(answer.rescode, ResultCode::NxDomain);
    }

    #[test]
    fn nodata_for_wrong_type() {
        let answer = store()
            .lookup(&DnsQuestion::new("www.example.com".into(), QueryType::MX))
            .unwrap();
        assert_eq!(answer.rescode, ResultCode::NoError);
        assert!(answer.answers.is_empty());
    }

    #[test]
    fn unhosted_name_returns_none() {
        assert!(
            store()
                .lookup(&DnsQuestion::new("google.com".into(), QueryType::A))
                .is_none()
        );
    }
}
