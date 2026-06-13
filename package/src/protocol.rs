use std::net::{Ipv4Addr, Ipv6Addr};

use crate::buffer::BytePacketBuffer;
use crate::error::Result;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> Self {
        match num {
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NxDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            _ => Self::NoError,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16,
    pub recursion_desired: bool,
    pub truncated_message: bool,
    pub authoritative_answer: bool,
    pub opcode: u8,
    pub response: bool,
    pub rescode: ResultCode,
    pub checking_disabled: bool,
    pub authed_data: bool,
    pub z: bool,
    pub recursion_available: bool,
    pub questions: u16,
    pub answers: u16,
    pub authoritative_entries: u16,
    pub resource_entries: u16,
}

impl DnsHeader {
    pub fn new() -> Self {
        Self {
            id: 0,
            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,
            rescode: ResultCode::NoError,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,
            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let high = (flags >> 8) as u8;
        let low = (flags & 0xFF) as u8;

        self.recursion_desired = (high & (1 << 0)) > 0;
        self.truncated_message = (high & (1 << 1)) > 0;
        self.authoritative_answer = (high & (1 << 2)) > 0;
        self.opcode = (high >> 3) & 0x0F;
        self.response = (high & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(low & 0x0F);
        self.checking_disabled = (low & (1 << 4)) > 0;
        self.authed_data = (low & (1 << 5)) > 0;
        self.z = (low & (1 << 6)) > 0;
        self.recursion_available = (low & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7),
        )?;

        buffer.write_u8(
            (self.rescode as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}

impl Default for DnsHeader {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    Unknown(u16),
    A,
    NS,
    CNAME,
    SOA,
    MX,
    TXT,
    AAAA,
    DS,
    RRSIG,
    NSEC,
    DNSKEY,
    NSEC3,
    OPT,
}

impl QueryType {
    pub fn to_num(self) -> u16 {
        match self {
            Self::Unknown(num) => num,
            Self::A => 1,
            Self::NS => 2,
            Self::CNAME => 5,
            Self::SOA => 6,
            Self::MX => 15,
            Self::TXT => 16,
            Self::AAAA => 28,
            Self::DS => 43,
            Self::RRSIG => 46,
            Self::NSEC => 47,
            Self::DNSKEY => 48,
            Self::NSEC3 => 50,
            Self::OPT => 41,
        }
    }

    pub fn from_num(num: u16) -> Self {
        match num {
            1 => Self::A,
            2 => Self::NS,
            5 => Self::CNAME,
            6 => Self::SOA,
            15 => Self::MX,
            16 => Self::TXT,
            28 => Self::AAAA,
            43 => Self::DS,
            46 => Self::RRSIG,
            47 => Self::NSEC,
            48 => Self::DNSKEY,
            50 => Self::NSEC3,
            41 => Self::OPT,
            _ => Self::Unknown(num),
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_uppercase().as_str() {
            "A" => Ok(Self::A),
            "NS" => Ok(Self::NS),
            "CNAME" => Ok(Self::CNAME),
            "SOA" => Ok(Self::SOA),
            "MX" => Ok(Self::MX),
            "TXT" => Ok(Self::TXT),
            "AAAA" => Ok(Self::AAAA),
            "DS" => Ok(Self::DS),
            "RRSIG" => Ok(Self::RRSIG),
            "NSEC" => Ok(Self::NSEC),
            "DNSKEY" => Ok(Self::DNSKEY),
            "NSEC3" => Ok(Self::NSEC3),
            other => {
                let value = other.parse::<u16>()?;
                Ok(Self::from_num(value))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> Self {
        Self { name, qtype }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        let _class = buffer.read_u16()?;
        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_qname(&self.name)?;
        buffer.write_u16(self.qtype.to_num())?;
        buffer.write_u16(1)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DnsRecord {
    Unknown {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    },
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    NS {
        domain: String,
        host: String,
        ttl: u32,
    },
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    },
    SOA {
        domain: String,
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
        ttl: u32,
    },
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    },
    TXT {
        domain: String,
        text: String,
        ttl: u32,
    },
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    },
    /// Delegation Signer: links a child zone's DNSKEY to the parent. (type 43)
    DS {
        domain: String,
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
        ttl: u32,
    },
    /// Signature over an RRset. (type 46)
    RRSIG {
        domain: String,
        type_covered: u16,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        expiration: u32,
        inception: u32,
        key_tag: u16,
        signer_name: String,
        signature: Vec<u8>,
        ttl: u32,
    },
    /// Authenticated denial of existence. (type 47)
    NSEC {
        domain: String,
        next_domain: String,
        type_bitmaps: Vec<u8>,
        ttl: u32,
    },
    /// A public key used to verify RRSIGs in a zone. (type 48)
    DNSKEY {
        domain: String,
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: Vec<u8>,
        ttl: u32,
    },
    /// Hashed authenticated denial of existence. Carried verbatim. (type 50)
    NSEC3 {
        domain: String,
        rdata: Vec<u8>,
        ttl: u32,
    },
    /// EDNS(0) pseudo-record carrying the advertised UDP payload size and the
    /// DNSSEC OK (DO) flag. Lives only in the additional section. (type 41)
    OPT {
        udp_payload_size: u16,
        extended_rcode: u8,
        version: u8,
        dnssec_ok: bool,
        data: Vec<u8>,
    },
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<Self> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let class = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    (raw_addr & 0xFF) as u8,
                );

                Ok(Self::A { domain, addr, ttl })
            }
            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    (raw_addr1 & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    (raw_addr2 & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    (raw_addr3 & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    (raw_addr4 & 0xFFFF) as u16,
                );

                Ok(Self::AAAA { domain, addr, ttl })
            }
            QueryType::NS => {
                let mut host = String::new();
                buffer.read_qname(&mut host)?;
                Ok(Self::NS { domain, host, ttl })
            }
            QueryType::CNAME => {
                let mut host = String::new();
                buffer.read_qname(&mut host)?;
                Ok(Self::CNAME { domain, host, ttl })
            }
            QueryType::SOA => {
                let mut mname = String::new();
                buffer.read_qname(&mut mname)?;
                let mut rname = String::new();
                buffer.read_qname(&mut rname)?;
                let serial = buffer.read_u32()?;
                let refresh = buffer.read_u32()?;
                let retry = buffer.read_u32()?;
                let expire = buffer.read_u32()?;
                let minimum = buffer.read_u32()?;
                Ok(Self::SOA {
                    domain,
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                    ttl,
                })
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut host = String::new();
                buffer.read_qname(&mut host)?;
                Ok(Self::MX {
                    domain,
                    priority,
                    host,
                    ttl,
                })
            }
            QueryType::TXT => {
                // TXT rdata is one or more <length, bytes> character-strings.
                // We concatenate them into a single string for convenience.
                let end = buffer.pos() + data_len as usize;
                let mut text = String::new();
                while buffer.pos() < end {
                    let len = buffer.read()? as usize;
                    let chunk = buffer.read_bytes(len)?;
                    text.push_str(&String::from_utf8_lossy(&chunk));
                }
                Ok(Self::TXT { domain, text, ttl })
            }
            QueryType::DS => {
                let key_tag = buffer.read_u16()?;
                let algorithm = buffer.read()?;
                let digest_type = buffer.read()?;
                let digest = buffer.read_bytes(data_len as usize - 4)?;
                Ok(Self::DS {
                    domain,
                    key_tag,
                    algorithm,
                    digest_type,
                    digest,
                    ttl,
                })
            }
            QueryType::RRSIG => {
                let rdata_start = buffer.pos();
                let type_covered = buffer.read_u16()?;
                let algorithm = buffer.read()?;
                let labels = buffer.read()?;
                let original_ttl = buffer.read_u32()?;
                let expiration = buffer.read_u32()?;
                let inception = buffer.read_u32()?;
                let key_tag = buffer.read_u16()?;

                let mut signer_name = String::new();
                buffer.read_qname(&mut signer_name)?;

                let consumed = buffer.pos() - rdata_start;
                let signature = buffer.read_bytes(data_len as usize - consumed)?;

                Ok(Self::RRSIG {
                    domain,
                    type_covered,
                    algorithm,
                    labels,
                    original_ttl,
                    expiration,
                    inception,
                    key_tag,
                    signer_name,
                    signature,
                    ttl,
                })
            }
            QueryType::NSEC => {
                let rdata_start = buffer.pos();
                let mut next_domain = String::new();
                buffer.read_qname(&mut next_domain)?;
                let consumed = buffer.pos() - rdata_start;
                let type_bitmaps = buffer.read_bytes(data_len as usize - consumed)?;
                Ok(Self::NSEC {
                    domain,
                    next_domain,
                    type_bitmaps,
                    ttl,
                })
            }
            QueryType::DNSKEY => {
                let flags = buffer.read_u16()?;
                let protocol = buffer.read()?;
                let algorithm = buffer.read()?;
                let public_key = buffer.read_bytes(data_len as usize - 4)?;
                Ok(Self::DNSKEY {
                    domain,
                    flags,
                    protocol,
                    algorithm,
                    public_key,
                    ttl,
                })
            }
            QueryType::NSEC3 => {
                let rdata = buffer.read_bytes(data_len as usize)?;
                Ok(Self::NSEC3 { domain, rdata, ttl })
            }
            QueryType::OPT => {
                // For OPT the "class" field is the advertised UDP payload size
                // and the "ttl" field packs the extended rcode, version, and
                // flags (the top bit being DNSSEC OK).
                let data = buffer.read_bytes(data_len as usize)?;
                Ok(Self::OPT {
                    udp_payload_size: class,
                    extended_rcode: (ttl >> 24) as u8,
                    version: (ttl >> 16) as u8,
                    dnssec_ok: (ttl & 0x0000_8000) != 0,
                    data,
                })
            }
            QueryType::Unknown(_) => {
                buffer.step(data_len as usize)?;
                Ok(Self::Unknown {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl,
                })
            }
        }
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start_pos = buffer.pos();

        match self {
            Self::A { domain, addr, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16(4)?;

                for octet in addr.octets() {
                    buffer.write_u8(octet)?;
                }
            }
            Self::NS { domain, host, ttl } => {
                write_name_record(buffer, domain, QueryType::NS, *ttl, host)?;
            }
            Self::CNAME { domain, host, ttl } => {
                write_name_record(buffer, domain, QueryType::CNAME, *ttl, host)?;
            }
            Self::SOA {
                domain,
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::SOA.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;

                let data_len_pos = buffer.pos();
                buffer.write_u16(0)?;
                buffer.write_qname(mname)?;
                buffer.write_qname(rname)?;
                buffer.write_u32(*serial)?;
                buffer.write_u32(*refresh)?;
                buffer.write_u32(*retry)?;
                buffer.write_u32(*expire)?;
                buffer.write_u32(*minimum)?;

                let size = buffer.pos() - (data_len_pos + 2);
                buffer.set_u16(data_len_pos, size as u16)?;
            }
            Self::MX {
                domain,
                priority,
                host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;

                let data_len_pos = buffer.pos();
                buffer.write_u16(0)?;
                buffer.write_u16(*priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (data_len_pos + 2);
                buffer.set_u16(data_len_pos, size as u16)?;
            }
            Self::TXT { domain, text, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::TXT.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;

                let data_len_pos = buffer.pos();
                buffer.write_u16(0)?;
                // Emit as 255-byte character-strings, as the wire format requires.
                for chunk in text.as_bytes().chunks(255) {
                    buffer.write_u8(chunk.len() as u8)?;
                    buffer.write_bytes(chunk)?;
                }

                let size = buffer.pos() - (data_len_pos + 2);
                buffer.set_u16(data_len_pos, size as u16)?;
            }
            Self::AAAA { domain, addr, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16(16)?;

                for segment in addr.segments() {
                    buffer.write_u16(segment)?;
                }
            }
            Self::DS {
                domain,
                key_tag,
                algorithm,
                digest_type,
                digest,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::DS.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16((4 + digest.len()) as u16)?;
                buffer.write_u16(*key_tag)?;
                buffer.write_u8(*algorithm)?;
                buffer.write_u8(*digest_type)?;
                buffer.write_bytes(digest)?;
            }
            Self::RRSIG {
                domain,
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                signer_name,
                signature,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::RRSIG.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;

                let data_len_pos = buffer.pos();
                buffer.write_u16(0)?;
                buffer.write_u16(*type_covered)?;
                buffer.write_u8(*algorithm)?;
                buffer.write_u8(*labels)?;
                buffer.write_u32(*original_ttl)?;
                buffer.write_u32(*expiration)?;
                buffer.write_u32(*inception)?;
                buffer.write_u16(*key_tag)?;
                buffer.write_qname(signer_name)?;
                buffer.write_bytes(signature)?;

                let size = buffer.pos() - (data_len_pos + 2);
                buffer.set_u16(data_len_pos, size as u16)?;
            }
            Self::NSEC {
                domain,
                next_domain,
                type_bitmaps,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NSEC.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;

                let data_len_pos = buffer.pos();
                buffer.write_u16(0)?;
                buffer.write_qname(next_domain)?;
                buffer.write_bytes(type_bitmaps)?;

                let size = buffer.pos() - (data_len_pos + 2);
                buffer.set_u16(data_len_pos, size as u16)?;
            }
            Self::DNSKEY {
                domain,
                flags,
                protocol,
                algorithm,
                public_key,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::DNSKEY.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16((4 + public_key.len()) as u16)?;
                buffer.write_u16(*flags)?;
                buffer.write_u8(*protocol)?;
                buffer.write_u8(*algorithm)?;
                buffer.write_bytes(public_key)?;
            }
            Self::NSEC3 { domain, rdata, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NSEC3.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16(rdata.len() as u16)?;
                buffer.write_bytes(rdata)?;
            }
            Self::OPT {
                udp_payload_size,
                extended_rcode,
                version,
                dnssec_ok,
                data,
            } => {
                // Root name, then type, then the repurposed class/ttl fields.
                buffer.write_u8(0)?;
                buffer.write_u16(QueryType::OPT.to_num())?;
                buffer.write_u16(*udp_payload_size)?;
                let ttl = ((*extended_rcode as u32) << 24)
                    | ((*version as u32) << 16)
                    | (if *dnssec_ok { 0x0000_8000 } else { 0 });
                buffer.write_u32(ttl)?;
                buffer.write_u16(data.len() as u16)?;
                buffer.write_bytes(data)?;
            }
            Self::Unknown { .. } => {}
        }

        Ok(buffer.pos() - start_pos)
    }

    pub fn ttl(&self) -> u32 {
        match self {
            Self::Unknown { ttl, .. }
            | Self::A { ttl, .. }
            | Self::NS { ttl, .. }
            | Self::CNAME { ttl, .. }
            | Self::SOA { ttl, .. }
            | Self::MX { ttl, .. }
            | Self::TXT { ttl, .. }
            | Self::AAAA { ttl, .. }
            | Self::DS { ttl, .. }
            | Self::RRSIG { ttl, .. }
            | Self::NSEC { ttl, .. }
            | Self::DNSKEY { ttl, .. }
            | Self::NSEC3 { ttl, .. } => *ttl,
            // The OPT pseudo-record has no TTL of its own.
            Self::OPT { .. } => 0,
        }
    }

    pub fn with_ttl(&self, new_ttl: u32) -> Self {
        let mut record = self.clone();

        match &mut record {
            Self::Unknown { ttl, .. }
            | Self::A { ttl, .. }
            | Self::NS { ttl, .. }
            | Self::CNAME { ttl, .. }
            | Self::SOA { ttl, .. }
            | Self::MX { ttl, .. }
            | Self::TXT { ttl, .. }
            | Self::AAAA { ttl, .. }
            | Self::DS { ttl, .. }
            | Self::RRSIG { ttl, .. }
            | Self::NSEC { ttl, .. }
            | Self::DNSKEY { ttl, .. }
            | Self::NSEC3 { ttl, .. } => *ttl = new_ttl,
            Self::OPT { .. } => {}
        }

        record
    }

    /// The owner name of this record, if it has one (everything but OPT).
    pub fn domain(&self) -> Option<&str> {
        match self {
            Self::Unknown { domain, .. }
            | Self::A { domain, .. }
            | Self::NS { domain, .. }
            | Self::CNAME { domain, .. }
            | Self::SOA { domain, .. }
            | Self::MX { domain, .. }
            | Self::TXT { domain, .. }
            | Self::AAAA { domain, .. }
            | Self::DS { domain, .. }
            | Self::RRSIG { domain, .. }
            | Self::NSEC { domain, .. }
            | Self::DNSKEY { domain, .. }
            | Self::NSEC3 { domain, .. } => Some(domain),
            Self::OPT { .. } => None,
        }
    }
}

fn write_name_record(
    buffer: &mut BytePacketBuffer,
    domain: &str,
    qtype: QueryType,
    ttl: u32,
    host: &str,
) -> Result<()> {
    buffer.write_qname(domain)?;
    buffer.write_u16(qtype.to_num())?;
    buffer.write_u16(1)?;
    buffer.write_u32(ttl)?;

    let data_len_pos = buffer.pos();
    buffer.write_u16(0)?;
    buffer.write_qname(host)?;

    let size = buffer.pos() - (data_len_pos + 2);
    buffer.set_u16(data_len_pos, size as u16)?;

    Ok(())
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> Self {
        Self {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<Self> {
        let mut result = Self::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new(String::new(), QueryType::Unknown(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            result.answers.push(DnsRecord::read(buffer)?);
        }

        for _ in 0..result.header.authoritative_entries {
            result.authorities.push(DnsRecord::read(buffer)?);
        }

        for _ in 0..result.header.resource_entries {
            result.resources.push(DnsRecord::read(buffer)?);
        }

        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }

        for record in &self.answers {
            record.write(buffer)?;
        }

        for record in &self.authorities {
            record.write(buffer)?;
        }

        for record in &self.resources {
            record.write(buffer)?;
        }

        Ok(())
    }

    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        self.answers.iter().find_map(|record| match record {
            DnsRecord::A { addr, .. } => Some(*addr),
            _ => None,
        })
    }

    fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities
            .iter()
            .filter_map(|record| match record {
                DnsRecord::NS { domain, host, .. } => Some((domain.as_str(), host.as_str())),
                _ => None,
            })
            .filter(move |(domain, _)| qname.ends_with(*domain))
    }

    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        self.get_ns(qname)
            .flat_map(|(_, host)| {
                self.resources
                    .iter()
                    .filter_map(move |record| match record {
                        DnsRecord::A { domain, addr, .. } if domain == host => Some(*addr),
                        _ => None,
                    })
            })
            .next()
    }

    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        self.get_ns(qname).map(|(_, host)| host).next()
    }

    /// Attach an EDNS(0) OPT record to the additional section, advertising a
    /// larger UDP payload size and optionally setting the DNSSEC OK (DO) flag.
    pub fn set_edns(&mut self, udp_payload_size: u16, dnssec_ok: bool) {
        self.resources.retain(|r| !matches!(r, DnsRecord::OPT { .. }));
        self.resources.push(DnsRecord::OPT {
            udp_payload_size,
            extended_rcode: 0,
            version: 0,
            dnssec_ok,
            data: Vec::new(),
        });
    }

    /// The OPT pseudo-record carried by this packet, if any.
    pub fn edns(&self) -> Option<&DnsRecord> {
        self.resources
            .iter()
            .chain(self.answers.iter())
            .chain(self.authorities.iter())
            .find(|r| matches!(r, DnsRecord::OPT { .. }))
    }

    /// Whether the sender set the DNSSEC OK (DO) flag.
    pub fn dnssec_ok(&self) -> bool {
        matches!(self.edns(), Some(DnsRecord::OPT { dnssec_ok: true, .. }))
    }

    /// The largest response the peer will accept over UDP. Falls back to the
    /// classic 512-byte limit when no EDNS OPT record is present.
    pub fn max_udp_payload(&self) -> usize {
        match self.edns() {
            Some(DnsRecord::OPT {
                udp_payload_size, ..
            }) => (*udp_payload_size as usize).max(crate::buffer::DNS_PACKET_SIZE),
            _ => crate::buffer::DNS_PACKET_SIZE,
        }
    }
}

impl Default for DnsPacket {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compressed_a_response() {
        let bytes = [
            0x86, 0x2a, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, b'g',
            b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x25, 0x00, 0x04, 0xd8, 0x3a,
            0xd3, 0x8e,
        ];

        let mut buffer = BytePacketBuffer::new();
        buffer.buf[..bytes.len()].copy_from_slice(&bytes);

        let packet = DnsPacket::from_buffer(&mut buffer).unwrap();

        assert_eq!(packet.header.id, 0x862a);
        assert_eq!(packet.header.rescode, ResultCode::NoError);
        assert_eq!(packet.questions[0].name, "google.com");
        assert_eq!(packet.questions[0].qtype, QueryType::A);
        assert_eq!(
            packet.answers[0],
            DnsRecord::A {
                domain: "google.com".to_string(),
                addr: Ipv4Addr::new(216, 58, 211, 142),
                ttl: 293,
            }
        );
    }

    #[test]
    fn writes_question_packet() {
        let mut packet = DnsPacket::new();
        packet.header.id = 0x1234;
        packet
            .questions
            .push(DnsQuestion::new("google.com".to_string(), QueryType::A));

        let mut buffer = BytePacketBuffer::new();
        packet.write(&mut buffer).unwrap();

        assert_eq!(&buffer.buf[0..2], &[0x12, 0x34]);
        assert_eq!(&buffer.buf[4..6], &[0x00, 0x01]);
        assert_eq!(
            &buffer.buf[12..24],
            &[
                0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00
            ]
        );
    }

    fn round_trip(record: DnsRecord) -> DnsRecord {
        let mut buffer = BytePacketBuffer::new();
        record.write(&mut buffer).unwrap();
        buffer.seek(0).unwrap();
        DnsRecord::read(&mut buffer).unwrap()
    }

    #[test]
    fn soa_and_txt_round_trip() {
        let soa = DnsRecord::SOA {
            domain: "example.com".into(),
            mname: "ns1.example.com".into(),
            rname: "admin.example.com".into(),
            serial: 2024010101,
            refresh: 7200,
            retry: 3600,
            expire: 1209600,
            minimum: 3600,
            ttl: 3600,
        };
        assert_eq!(round_trip(soa.clone()), soa);

        let txt = DnsRecord::TXT {
            domain: "example.com".into(),
            text: "v=spf1 -all".into(),
            ttl: 300,
        };
        assert_eq!(round_trip(txt.clone()), txt);
    }

    #[test]
    fn dnssec_records_round_trip() {
        let ds = DnsRecord::DS {
            domain: "example.com".into(),
            key_tag: 12345,
            algorithm: 8,
            digest_type: 2,
            digest: vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x11],
            ttl: 86400,
        };
        assert_eq!(round_trip(ds.clone()), ds);

        let rrsig = DnsRecord::RRSIG {
            domain: "example.com".into(),
            type_covered: 1,
            algorithm: 8,
            labels: 2,
            original_ttl: 300,
            expiration: 1700000000,
            inception: 1690000000,
            key_tag: 54321,
            signer_name: "example.com".into(),
            signature: vec![0x01, 0x02, 0x03, 0x04, 0x05],
            ttl: 300,
        };
        assert_eq!(round_trip(rrsig.clone()), rrsig);
    }

    #[test]
    fn edns_opt_round_trips_dnssec_ok() {
        let mut packet = DnsPacket::new();
        packet
            .questions
            .push(DnsQuestion::new("example.com".into(), QueryType::A));
        packet.set_edns(4096, true);

        let mut buffer = BytePacketBuffer::new();
        packet.write(&mut buffer).unwrap();
        buffer.seek(0).unwrap();

        let parsed = DnsPacket::from_buffer(&mut buffer).unwrap();
        assert!(parsed.dnssec_ok());
        assert_eq!(parsed.max_udp_payload(), 4096);
    }
}
