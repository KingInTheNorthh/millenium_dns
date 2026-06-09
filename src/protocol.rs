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
    MX,
    AAAA,
}

impl QueryType {
    pub fn to_num(self) -> u16 {
        match self {
            Self::Unknown(num) => num,
            Self::A => 1,
            Self::NS => 2,
            Self::CNAME => 5,
            Self::MX => 15,
            Self::AAAA => 28,
        }
    }

    pub fn from_num(num: u16) -> Self {
        match num {
            1 => Self::A,
            2 => Self::NS,
            5 => Self::CNAME,
            15 => Self::MX,
            28 => Self::AAAA,
            _ => Self::Unknown(num),
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_uppercase().as_str() {
            "A" => Ok(Self::A),
            "NS" => Ok(Self::NS),
            "CNAME" => Ok(Self::CNAME),
            "MX" => Ok(Self::MX),
            "AAAA" => Ok(Self::AAAA),
            other => {
                let value = other.parse::<u16>()?;
                Ok(Self::Unknown(value))
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
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    },
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    },
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<Self> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _class = buffer.read_u16()?;
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
            | Self::MX { ttl, .. }
            | Self::AAAA { ttl, .. } => *ttl,
        }
    }

    pub fn with_ttl(&self, new_ttl: u32) -> Self {
        let mut record = self.clone();

        match &mut record {
            Self::Unknown { ttl, .. }
            | Self::A { ttl, .. }
            | Self::NS { ttl, .. }
            | Self::CNAME { ttl, .. }
            | Self::MX { ttl, .. }
            | Self::AAAA { ttl, .. } => *ttl = new_ttl,
        }

        record
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
}
