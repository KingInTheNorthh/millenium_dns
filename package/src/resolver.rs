use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::buffer::BytePacketBuffer;
use crate::error::{Result, dns_error};
use crate::protocol::{DnsPacket, DnsQuestion, QueryType, ResultCode};

const ROOT_SERVER: Ipv4Addr = Ipv4Addr::new(198, 41, 0, 4);
const DNS_PORT: u16 = 53;
const MAX_RECURSION_DEPTH: u8 = 16;
/// UDP payload size we advertise via EDNS(0) so DNSSEC-laden answers fit.
const EDNS_UDP_PAYLOAD: u16 = 4096;
const NETWORK_TIMEOUT: Duration = Duration::from_secs(5);

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

/// Issue a single query to `server`. Sent over UDP first; if the reply comes
/// back with the truncation (TC) bit set, the query is retried over TCP where
/// the 512-byte size limit doesn't apply.
fn lookup(qname: &str, qtype: QueryType, server: (Ipv4Addr, u16)) -> Result<DnsPacket> {
    let query = build_query(qname, qtype);
    let response = lookup_udp(&query, server)?;

    if response.header.truncated_message {
        println!("response truncated, retrying {} over TCP", qname);
        return lookup_tcp(&query, server);
    }

    Ok(response)
}

/// Build the query packet, advertising EDNS(0) with the DNSSEC OK bit so that
/// servers include RRSIG/DNSKEY/DS records in their replies.
fn build_query(qname: &str, qtype: QueryType) -> DnsPacket {
    let mut packet = DnsPacket::new();
    packet.header.id = next_query_id();
    packet.header.recursion_desired = false;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));
    packet.set_edns(EDNS_UDP_PAYLOAD, true);
    packet
}

/// Number of times to resend a UDP query if no reply arrives, since a single
/// dropped datagram should not abort an entire resolution.
const UDP_RETRIES: u32 = 3;

fn lookup_udp(query: &DnsPacket, server: (Ipv4Addr, u16)) -> Result<DnsPacket> {
    let socket = UdpSocket::bind(("0.0.0.0", 0))?;
    socket.set_read_timeout(Some(NETWORK_TIMEOUT))?;
    socket.set_write_timeout(Some(NETWORK_TIMEOUT))?;

    let mut req_buffer = BytePacketBuffer::new();
    let mut query = query.clone();
    query.write(&mut req_buffer)?;
    let request = &req_buffer.buf[..req_buffer.pos()];

    let mut last_error = None;
    for _ in 0..UDP_RETRIES {
        socket.send_to(request, server)?;

        let mut res_buffer = BytePacketBuffer::new();
        match socket.recv_from(&mut res_buffer.buf) {
            Ok(_) => return DnsPacket::from_buffer(&mut res_buffer),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                last_error = Some(error);
                continue;
            }
            Err(error) => return Err(error.into()),
        }
    }

    Err(last_error
        .map(Into::into)
        .unwrap_or_else(|| dns_error("UDP query timed out")))
}

fn lookup_tcp(query: &DnsPacket, server: (Ipv4Addr, u16)) -> Result<DnsPacket> {
    let mut stream = TcpStream::connect(server)?;
    stream.set_read_timeout(Some(NETWORK_TIMEOUT))?;
    stream.set_write_timeout(Some(NETWORK_TIMEOUT))?;

    let mut req_buffer = BytePacketBuffer::new();
    let mut query = query.clone();
    query.write(&mut req_buffer)?;

    write_tcp_message(&mut stream, &req_buffer.buf[..req_buffer.pos()])?;

    let mut res_buffer = read_tcp_message(&mut stream)?;
    DnsPacket::from_buffer(&mut res_buffer)
}

/// Write a DNS message over TCP, framed by the mandatory 2-byte length prefix.
pub fn write_tcp_message(stream: &mut TcpStream, message: &[u8]) -> Result<()> {
    let len = u16::try_from(message.len())
        .map_err(|_| dns_error("DNS message exceeds 65535 bytes"))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(message)?;
    stream.flush()?;
    Ok(())
}

/// Read a length-prefixed DNS message over TCP into a fresh buffer.
pub fn read_tcp_message(stream: &mut TcpStream) -> Result<BytePacketBuffer> {
    let mut len_bytes = [0u8; 2];
    stream.read_exact(&mut len_bytes)?;
    let len = u16::from_be_bytes(len_bytes) as usize;

    let mut buffer = BytePacketBuffer::new();
    if len > buffer.buf.len() {
        return Err(dns_error("Declared TCP message length exceeds buffer"));
    }
    stream.read_exact(&mut buffer.buf[..len])?;

    Ok(buffer)
}

fn next_query_id() -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos())
        .unwrap_or(0);

    (nanos & 0xFFFF) as u16
}
