use std::net::{Ipv4Addr, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::buffer::BytePacketBuffer;
use crate::error::{Result, dns_error};
use crate::protocol::{DnsPacket, DnsQuestion, QueryType, ResultCode};

const ROOT_SERVER: Ipv4Addr = Ipv4Addr::new(198, 41, 0, 4);
const DNS_PORT: u16 = 53;
const MAX_RECURSION_DEPTH: u8 = 16;

pub fn recursive_lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket> {
    recursive_lookup_inner(qname, qtype, 0)
}

fn recursive_lookup_inner(qname: &str, qtype: QueryType, depth: u8) -> Result<DnsPacket> {
    if depth > MAX_RECURSION_DEPTH {
        return Err(dns_error("Maximum recursive lookup depth exceeded"));
    }

    let mut name_server = ROOT_SERVER;

    loop {
        println!(
            "attempting lookup of {:?} {} with ns {}",
            qtype, qname, name_server
        );

        let response = lookup(qname, qtype, (name_server, DNS_PORT))?;

        if !response.answers.is_empty() && response.header.rescode == ResultCode::NoError {
            return Ok(response);
        }

        if response.header.rescode == ResultCode::NxDomain {
            return Ok(response);
        }

        if let Some(new_name_server) = response.get_resolved_ns(qname) {
            name_server = new_name_server;
            continue;
        }

        let Some(new_name_server_name) = response.get_unresolved_ns(qname) else {
            return Ok(response);
        };

        let recursive_response =
            recursive_lookup_inner(new_name_server_name, QueryType::A, depth + 1)?;

        if let Some(new_name_server) = recursive_response.get_random_a() {
            name_server = new_name_server;
        } else {
            return Ok(response);
        }
    }
}

fn lookup(qname: &str, qtype: QueryType, server: (Ipv4Addr, u16)) -> Result<DnsPacket> {
    let socket = UdpSocket::bind(("0.0.0.0", 0))?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;

    let mut packet = DnsPacket::new();
    packet.header.id = next_query_id();
    packet.header.questions = 1;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;
    socket.send_to(&req_buffer.buf[..req_buffer.pos()], server)?;

    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf)?;

    DnsPacket::from_buffer(&mut res_buffer)
}

fn next_query_id() -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos())
        .unwrap_or(0);

    (nanos & 0xFFFF) as u16
}
