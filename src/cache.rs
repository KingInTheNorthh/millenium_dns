use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::protocol::{DnsPacket, DnsQuestion, DnsRecord, QueryType, ResultCode};

#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub rescode: ResultCode,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

#[derive(Debug, Default)]
pub struct ResponseCache {
    entries: HashMap<CacheKey, CacheEntry>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct CacheKey {
    name: String,
    qtype: QueryType,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    rescode: ResultCode,
    answers: Vec<CachedRecord>,
    authorities: Vec<CachedRecord>,
    resources: Vec<CachedRecord>,
}

#[derive(Debug, Clone)]
struct CachedRecord {
    record: DnsRecord,
    expires_at: Instant,
}

impl ResponseCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&mut self, question: &DnsQuestion) -> Option<CachedResponse> {
        let key = CacheKey::from_question(question);
        let now = Instant::now();

        let Some(entry) = self.entries.get(&key) else {
            return None;
        };

        let answers = live_records(&entry.answers, now);

        if answers.is_empty() {
            self.entries.remove(&key);
            return None;
        }

        Some(CachedResponse {
            rescode: entry.rescode,
            answers,
            authorities: live_records(&entry.authorities, now),
            resources: live_records(&entry.resources, now),
        })
    }

    pub fn insert(&mut self, question: &DnsQuestion, packet: &DnsPacket) {
        if packet.header.rescode != ResultCode::NoError || packet.answers.is_empty() {
            return;
        }

        let now = Instant::now();
        let answers = cache_records(&packet.answers, now);

        if answers.is_empty() {
            return;
        }

        self.entries.insert(
            CacheKey::from_question(question),
            CacheEntry {
                rescode: packet.header.rescode,
                answers,
                authorities: cache_records(&packet.authorities, now),
                resources: cache_records(&packet.resources, now),
            },
        );
    }
}

impl CacheKey {
    fn from_question(question: &DnsQuestion) -> Self {
        Self {
            name: question.name.trim_end_matches('.').to_ascii_lowercase(),
            qtype: question.qtype,
        }
    }
}

fn cache_records(records: &[DnsRecord], now: Instant) -> Vec<CachedRecord> {
    records
        .iter()
        .filter_map(|record| {
            let ttl = record.ttl();

            if ttl == 0 {
                return None;
            }

            Some(CachedRecord {
                record: record.clone(),
                expires_at: now + Duration::from_secs(ttl as u64),
            })
        })
        .collect()
}

fn live_records(records: &[CachedRecord], now: Instant) -> Vec<DnsRecord> {
    records
        .iter()
        .filter_map(|cached| {
            let remaining = cached.expires_at.checked_duration_since(now)?;
            let ttl = remaining.as_secs().clamp(1, u32::MAX as u64) as u32;
            Some(cached.record.with_ttl(ttl))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn returns_cached_answers_with_ttl() {
        let question = DnsQuestion::new("Example.COM.".to_string(), QueryType::A);
        let mut packet = DnsPacket::new();
        packet.header.rescode = ResultCode::NoError;
        packet.answers.push(DnsRecord::A {
            domain: "example.com".to_string(),
            addr: Ipv4Addr::new(93, 184, 216, 34),
            ttl: 300,
        });

        let mut cache = ResponseCache::new();
        cache.insert(&question, &packet);

        let cached = cache.get(&DnsQuestion::new("example.com".to_string(), QueryType::A));

        assert_eq!(cached.unwrap().answers.len(), 1);
    }
}
