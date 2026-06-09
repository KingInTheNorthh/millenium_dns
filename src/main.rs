use std::env;

use millenium_dns::error::{Result, dns_error};
use millenium_dns::protocol::QueryType;
use millenium_dns::resolver::recursive_lookup;
use millenium_dns::server::run_server;

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

fn print_usage(program: &str) {
    eprintln!("Usage:");
    eprintln!("  {program} serve [bind_addr]");
    eprintln!("  {program} lookup <domain> [A|AAAA|NS|CNAME|MX|type_num]");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {program} serve 127.0.0.1:2053");
    eprintln!("  {program} lookup example.com A");
}

fn main() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    let program = args.first().map(String::as_str).unwrap_or("millenium-dns");

    match args.get(1).map(String::as_str) {
        Some("serve") => {
            let bind_addr = args.get(2).map(String::as_str).unwrap_or("127.0.0.1:2053");
            run_server(bind_addr)
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
        _ => {
            print_usage(program);
            Ok(())
        }
    }
}
