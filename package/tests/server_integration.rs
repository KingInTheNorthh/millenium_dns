//! End-to-end tests that boot the server and query it over UDP and TCP.
//!
//! These exercise the parts that unit tests can't reach on their own:
//! authoritative zone answers, the TCP transport with its length framing,
//! concurrent handling, and UDP truncation with TCP fallback.

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

use millenium_dns::buffer::BytePacketBuffer;
use millenium_dns::protocol::{DnsPacket, DnsQuestion, DnsRecord, QueryType};
use millenium_dns::server::run_server;
use millenium_dns::zone::ZoneStore;

const ADDR: &str = "127.0.0.1:39353";

/// A zone with enough large TXT records at one name to overflow a 512-byte
/// UDP response, so we can observe truncation.
const ZONE: &str = "\
$ORIGIN example.com.
$TTL 3600
@    IN SOA ns1.example.com. admin.example.com. ( 1 7200 3600 1209600 3600 )
@    IN NS  ns1.example.com.
@    IN A   93.184.216.34
www  IN A   93.184.216.34
ftp  IN CNAME www.example.com.
big  IN TXT \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"
big  IN TXT \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"
big  IN TXT \"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"
big  IN TXT \"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\"
big  IN TXT \"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\"
";

fn boot_server() {
    let dir = std::env::temp_dir();
    let path = dir.join("millenium_it_example.com.zone");
    std::fs::write(&path, ZONE).unwrap();
    let zones = ZoneStore::load_files(&[path]).unwrap();

    thread::spawn(move || {
        let _ = run_server(ADDR, zones);
    });

    // Give both listeners a moment to bind.
    thread::sleep(Duration::from_millis(300));
}

fn build_query(name: &str, qtype: QueryType, edns: bool) -> Vec<u8> {
    let mut packet = DnsPacket::new();
    packet.header.id = 0x4242;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(name.to_string(), qtype));
    if edns {
        packet.set_edns(4096, false);
    }

    let mut buffer = BytePacketBuffer::new();
    packet.write(&mut buffer).unwrap();
    buffer.buf[..buffer.pos()].to_vec()
}

fn query_udp(name: &str, qtype: QueryType, edns: bool) -> DnsPacket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket.send_to(&build_query(name, qtype, edns), ADDR).unwrap();

    let mut response = BytePacketBuffer::new();
    socket.recv_from(&mut response.buf).unwrap();
    DnsPacket::from_buffer(&mut response).unwrap()
}

fn query_tcp(name: &str, qtype: QueryType) -> DnsPacket {
    let mut stream = TcpStream::connect(ADDR).unwrap();
    let message = build_query(name, qtype, false);

    stream
        .write_all(&(message.len() as u16).to_be_bytes())
        .unwrap();
    stream.write_all(&message).unwrap();

    let mut len_bytes = [0u8; 2];
    stream.read_exact(&mut len_bytes).unwrap();
    let len = u16::from_be_bytes(len_bytes) as usize;

    let mut response = BytePacketBuffer::new();
    stream.read_exact(&mut response.buf[..len]).unwrap();
    DnsPacket::from_buffer(&mut response).unwrap()
}

#[test]
fn server_end_to_end() {
    boot_server();

    // Authoritative A answer over UDP.
    let response = query_udp("www.example.com", QueryType::A, false);
    assert!(response.header.authoritative_answer, "expected AA bit");
    assert!(
        response
            .answers
            .iter()
            .any(|r| matches!(r, DnsRecord::A { .. })),
        "expected an A record, got {:?}",
        response.answers
    );

    // CNAME answers an A query.
    let response = query_udp("ftp.example.com", QueryType::A, false);
    assert!(
        response
            .answers
            .iter()
            .any(|r| matches!(r, DnsRecord::CNAME { .. }))
    );

    // NXDOMAIN for a name in the zone that doesn't exist.
    let response = query_udp("nope.example.com", QueryType::A, false);
    assert_eq!(
        response.header.rescode,
        millenium_dns::protocol::ResultCode::NxDomain
    );

    // The same authoritative answer is reachable over TCP.
    let response = query_tcp("www.example.com", QueryType::A);
    assert!(response.header.authoritative_answer);
    assert!(
        response
            .answers
            .iter()
            .any(|r| matches!(r, DnsRecord::A { .. }))
    );

    // A large answer over UDP without EDNS must be truncated (TC set)...
    let udp = query_udp("big.example.com", QueryType::TXT, false);
    assert!(
        udp.header.truncated_message,
        "expected TC bit on oversized UDP answer"
    );
    assert!(udp.answers.is_empty(), "truncated answer should carry no records");

    // ...but the full record set comes back over TCP.
    let tcp = query_tcp("big.example.com", QueryType::TXT);
    assert!(!tcp.header.truncated_message);
    assert_eq!(tcp.answers.len(), 5, "expected all TXT records over TCP");
}
