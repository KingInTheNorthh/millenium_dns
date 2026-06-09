use std::net::{SocketAddr, UdpSocket};

use crate::buffer::BytePacketBuffer;
use crate::cache::{CachedResponse, ResponseCache};
use crate::error::Result;
use crate::protocol::{DnsPacket, ResultCode};
use crate::resolver::recursive_lookup;

pub fn run_server(bind_addr: &str) -> Result<()> {
    let socket = UdpSocket::bind(bind_addr)?;
    let mut cache = ResponseCache::new();

    println!("listening on udp://{}", socket.local_addr()?);

    loop {
        if let Err(error) = handle_query(&socket, &mut cache) {
            eprintln!("request handling failed: {}", error);
        }
    }
}

fn handle_query(socket: &UdpSocket, cache: &mut ResponseCache) -> Result<()> {
    let mut req_buffer = BytePacketBuffer::new();
    let (_, src) = socket.recv_from(&mut req_buffer.buf)?;

    let mut request = DnsPacket::from_buffer(&mut req_buffer)?;
    let mut packet = DnsPacket::new();

    packet.header.id = request.header.id;
    packet.header.recursion_desired = request.header.recursion_desired;
    packet.header.recursion_available = true;
    packet.header.response = true;

    if let Some(question) = request.questions.pop() {
        println!("received query from {}: {:?}", src, question);

        if let Some(cached) = cache.get(&question) {
            println!("cache hit: {:?}", question);
            packet.questions.push(question);
            apply_cached_response(&mut packet, cached);
        } else {
            match recursive_lookup(&question.name, question.qtype) {
                Ok(result) => {
                    cache.insert(&question, &result);
                    packet.questions.push(question);
                    packet.header.rescode = result.header.rescode;
                    packet.answers = result.answers;
                    packet.authorities = result.authorities;
                    packet.resources = result.resources;
                }
                Err(error) => {
                    eprintln!("lookup failed: {}", error);
                    packet.questions.push(question);
                    packet.header.rescode = ResultCode::ServFail;
                }
            }
        }
    } else {
        packet.header.rescode = ResultCode::FormErr;
    }

    send_packet(socket, src, &mut packet)
}

fn apply_cached_response(packet: &mut DnsPacket, cached: CachedResponse) {
    packet.header.rescode = cached.rescode;
    packet.answers = cached.answers;
    packet.authorities = cached.authorities;
    packet.resources = cached.resources;
}

fn send_packet(socket: &UdpSocket, src: SocketAddr, packet: &mut DnsPacket) -> Result<()> {
    let mut res_buffer = BytePacketBuffer::new();
    packet.write(&mut res_buffer)?;

    let len = res_buffer.pos();
    let data = res_buffer.get_range(0, len)?;
    socket.send_to(data, src)?;

    Ok(())
}
