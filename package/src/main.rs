use std::env;

use millenium_dns::error::{Result, dns_error};
use millenium_dns::protocol::QueryType;
use millenium_dns::resolver::recursive_lookup;
use millenium_dns::server::run_server;
use millenium_dns::verify::{ChainStatus, verify_chain};
use millenium_dns::zone::ZoneStore;

fn run_lookup(qname: &str, qtype: QueryType) -> Result<()> {
    let packet = recursive_lookup(qname, qtype)?;

    println!("{:#?}", packet.header);

    for question in packet.questions {
        println!("{:#?}", question);
    }

    for record in packet.answers {
        println!("{:#?}", record);
    }

    for record in packet.authorities {
        println!("{:#?}", record);
    }

    for record in packet.resources {
        println!("{:#?}", record);
    }

    Ok(())
}

fn run_verify(qname: &str, qtype: QueryType) -> Result<()> {
    let report = verify_chain(qname, qtype)?;

    println!("DNSSEC chain for {} {:?}", report.name, report.qtype);
    match &report.signer {
        Some(signer) => println!("  signed by zone: {signer}\n"),
        None => println!("  (no RRSIG on the answer)\n"),
    }

    for link in &report.links {
        let marker = match link.status {
            ChainStatus::Secure => "[ok]  ",
            ChainStatus::Insecure => "[insec]",
            ChainStatus::Bogus => "[BOGUS]",
            ChainStatus::Indeterminate => "[?]   ",
        };
        let zone = if link.zone.is_empty() { "." } else { &link.zone };
        println!("  {marker} {zone:<24} {}", link.detail);
    }

    println!(
        "\n  => {}",
        match report.overall {
            ChainStatus::Secure =>
                "SECURE — validated from the answer to the root trust anchor",
            ChainStatus::Insecure =>
                "INSECURE — an unsigned delegation breaks the chain (data not protected)",
            ChainStatus::Bogus =>
                "BOGUS — a signature or DS failed to verify (possible tampering)",
            ChainStatus::Indeterminate =>
                "INDETERMINATE — unsupported algorithm (e.g. ECDSA) or missing records",
        }
    );

    Ok(())
}

fn print_usage(program: &str) {
    eprintln!("Usage:");
    eprintln!("  {program} serve [bind_addr] [zonefile...]");
    eprintln!("  {program} lookup <domain> [A|AAAA|NS|CNAME|SOA|MX|TXT|DS|DNSKEY|RRSIG|type_num]");
    eprintln!("  {program} verify <domain> [type]");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {program} serve 127.0.0.1:2053");
    eprintln!("  {program} serve 127.0.0.1:2053 zones/example.com.zone");
    eprintln!("  {program} lookup example.com A");
    eprintln!("  {program} verify cloudflare.com A");
}

fn main() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    let program = args.first().map(String::as_str).unwrap_or("millenium-dns");

    match args.get(1).map(String::as_str) {
        Some("serve") => {
            let bind_addr = args.get(2).map(String::as_str).unwrap_or("127.0.0.1:2053");

            let zone_files: Vec<&str> = args.iter().skip(3).map(String::as_str).collect();
            let zones = if zone_files.is_empty() {
                ZoneStore::empty()
            } else {
                let store = ZoneStore::load_files(&zone_files)?;
                println!("hosting zones: {}", store.origins().join(", "));
                store
            };

            run_server(bind_addr, zones)
        }
        Some("lookup") => {
            let Some(qname) = args.get(2) else {
                print_usage(program);
                return Err(dns_error("Missing domain for lookup"));
            };

            let qtype = args
                .get(3)
                .map(String::as_str)
                .map(QueryType::parse)
                .transpose()?
                .unwrap_or(QueryType::A);

            run_lookup(qname, qtype)
        }
        Some("verify") => {
            let Some(qname) = args.get(2) else {
                print_usage(program);
                return Err(dns_error("Missing domain for verify"));
            };

            let qtype = args
                .get(3)
                .map(String::as_str)
                .map(QueryType::parse)
                .transpose()?
                .unwrap_or(QueryType::A);

            run_verify(qname, qtype)
        }
        _ => {
            print_usage(program);
            Ok(())
        }
    }
}
