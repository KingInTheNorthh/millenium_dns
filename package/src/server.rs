use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::buffer::BytePacketBuffer;
use crate::cache::{CachedResponse, ResponseCache};
use crate::error::Result;
use crate::protocol::{DnsPacket, DnsRecord, ResultCode};
use crate::resolver::{read_tcp_message, recursive_lookup, write_tcp_message};
use crate::zone::ZoneStore;

/// UDP payload size the server advertises to clients via its own EDNS OPT.
const ADVERTISED_UDP_PAYLOAD: u16 = 4096;

/// Shared, thread-safe state every request handler needs.
pub struct ServerContext {
    cache: Mutex<ResponseCache>,
    zones: ZoneStore,
}

impl ServerContext {
    pub fn new(zones: ZoneStore) -> Self {
        Self {
            cache: Mutex::new(ResponseCache::new()),
            zones,
        }
    }
}

/// Bind UDP and TCP on `bind_addr` and serve queries concurrently.
pub fn run_server(bind_addr: &str, zones: ZoneStore) -> Result<()> {
    let context = Arc::new(ServerContext::new(zones));

    let udp_socket = UdpSocket::bind(bind_addr)?;
    let tcp_listener = TcpListener::bind(bind_addr)?;

    println!("listening on udp+tcp://{}", udp_socket.local_addr()?);

    // TCP gets its own acceptor thread; each connection is then handled on a
    // dedicated worker thread.
    let tcp_context = Arc::clone(&context);
    thread::spawn(move || serve_tcp(tcp_listener, tcp_context));

    serve_udp(udp_socket, context)
}

fn serve_udp(socket: UdpSocket, context: Arc<ServerContext>) -> Result<()> {
    let socket = Arc::new(socket);

    loop {
        let mut req_buffer = BytePacketBuffer::new();
        let (_, src) = match socket.recv_from(&mut req_buffer.buf) {
            Ok(result) => result,
            Err(error) => {
                eprintln!("udp recv failed: {}", error);
                continue;
            }
        };

        let socket = Arc::clone(&socket);
        let context = Arc::clone(&context);

        thread::spawn(move || {
            if let Err(error) = handle_udp(&socket, src, req_buffer, &context) {
                eprintln!("udp request from {} failed: {}", src, error);
            }
        });
    }
}

fn handle_udp(
    socket: &UdpSocket,
    src: SocketAddr,
    mut req_buffer: BytePacketBuffer,
    context: &ServerContext,
) -> Result<()> {
    let request = DnsPacket::from_buffer(&mut req_buffer)?;
    let max_payload = request.max_udp_payload();
    let mut response = build_response(request, context);

    let mut res_buffer = BytePacketBuffer::new();
    response.write(&mut res_buffer)?;

    // If the response overflows what the client will accept over UDP, drop the
    // record sections, set the truncation bit, and let the client retry on TCP.
    if res_buffer.pos() > max_payload {
        let mut truncated = truncate(&response);
        res_buffer = BytePacketBuffer::new();
        truncated.write(&mut res_buffer)?;
    }

    socket.send_to(&res_buffer.buf[..res_buffer.pos()], src)?;
    Ok(())
}

fn serve_tcp(listener: TcpListener, context: Arc<ServerContext>) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let context = Arc::clone(&context);
                thread::spawn(move || {
                    let peer = stream
                        .peer_addr()
                        .map(|addr| addr.to_string())
                        .unwrap_or_else(|_| "unknown".to_string());
                    if let Err(error) = handle_tcp(stream, &context) {
                        eprintln!("tcp request from {} failed: {}", peer, error);
                    }
                });
            }
            Err(error) => eprintln!("tcp accept failed: {}", error),
        }
    }
}

fn handle_tcp(mut stream: TcpStream, context: &ServerContext) -> Result<()> {
    let mut req_buffer = read_tcp_message(&mut stream)?;
    let request = DnsPacket::from_buffer(&mut req_buffer)?;

    let mut response = build_response(request, context);

    let mut res_buffer = BytePacketBuffer::new();
    response.write(&mut res_buffer)?;

    write_tcp_message(&mut stream, &res_buffer.buf[..res_buffer.pos()])
}

/// Turn a parsed request into a response packet: answer from local zones if we
/// own the name, otherwise from the cache, otherwise via recursive resolution.
fn build_response(mut request: DnsPacket, context: &ServerContext) -> DnsPacket {
    let dnssec_ok = request.dnssec_ok();

    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_desired = request.header.recursion_desired;
    packet.header.recursion_available = true;
    packet.header.response = true;

    if dnssec_ok {
        packet.set_edns(ADVERTISED_UDP_PAYLOAD, true);
    }

    let Some(question) = request.questions.pop() else {
        packet.header.rescode = ResultCode::FormErr;
        return packet;
    };

    println!("query: {:?} (do={})", question, dnssec_ok);
    packet.questions.push(question.clone());

    // 1. Authoritative answer from a locally hosted zone.
    if let Some(zone_answer) = context.zones.lookup(&question) {
        packet.header.authoritative_answer = true;
        packet.header.rescode = zone_answer.rescode;
        packet.answers = zone_answer.answers;
        packet.authorities = zone_answer.authorities;
        return packet;
    }

    // 2. Cached recursive answer.
    if let Some(cached) = context.cache.lock().unwrap().get(&question) {
        println!("cache hit: {:?}", question);
        apply_cached_response(&mut packet, cached);
        return packet;
    }

    // 3. Resolve recursively from the root servers.
    match recursive_lookup(&question.name, question.qtype) {
        Ok(result) => {
            context.cache.lock().unwrap().insert(&question, &result);
            packet.header.rescode = result.header.rescode;
            packet.answers = result.answers;
            packet.authorities = result.authorities;
            // Preserve DNSSEC material and glue, but don't clobber our OPT.
            packet
                .resources
                .extend(result.resources.into_iter().filter(|r| {
                    !matches!(r, DnsRecord::OPT { .. })
                }));
        }
        Err(error) => {
            eprintln!("lookup failed for {}: {}", question.name, error);
            packet.header.rescode = ResultCode::ServFail;
        }
    }

    packet
}

fn apply_cached_response(packet: &mut DnsPacket, cached: CachedResponse) {
    packet.header.rescode = cached.rescode;
    packet.answers = cached.answers;
    packet.authorities = cached.authorities;
    packet.resources.extend(cached.resources);
}

/// Produce a truncated copy of `response`: header (with TC set) and question
/// only, so an over-large UDP reply prompts the client to retry over TCP.
fn truncate(response: &DnsPacket) -> DnsPacket {
    let mut packet = DnsPacket::new();
    packet.header = response.header.clone();
    packet.header.truncated_message = true;
    packet.header.answers = 0;
    packet.header.authoritative_entries = 0;
    packet.header.resource_entries = 0;
    packet.questions = response.questions.clone();
    packet
}
