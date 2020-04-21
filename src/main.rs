extern crate clap;
use clap::{App, Arg};
mod dns;
use dns::server::DnsServer;
use dns::{context::ServerContext, resolver::ResolverMode, server::{UdpServer, TcpServer}};
use std::sync::Arc;

fn main() {
    // Get command line arguments
    let matches = App::new("rDNS")
        .author("MAKLs")
        .about("Recursive DNS resolver")
        .arg(
            Arg::with_name("mode")
                .short("m")
                .long("mode")
                .value_name("RESOLVER MODE")
                .possible_values(&["recursive", "forward"])
                .default_value("recursive"),
        )
        .arg(
            Arg::with_name("downstream_server")
                .short("s")
                .long("server")
                .value_name("DOWNSTREAM DNS SERVER")
                .required_if("mode", "forward"),
        )
        .arg(
            Arg::with_name("thread-count")
                .short("c")
                .long("thread-count")
                .default_value("5")
                .value_name("THREAD COUNT"),
        )
        .get_matches();
    println!("Starting rDNS\n");

    // Prepare server context
    let mut context = ServerContext::new();
    let resolver_mode = ResolverMode::from_str(
        matches.value_of("mode").unwrap(),
        matches.value_of("downstream_server"),
    );
    if let Some(mode) = resolver_mode {
        context.set_resolver_mode(mode);
    } else {
        context.set_resolver_mode(ResolverMode::Recursive);
    }

    let context_ptr = Arc::new(context);

    // Run servers
    let thread_count = matches
        .value_of("thread-count")
        .unwrap()
        .parse::<usize>()
        .expect("Failed to parse thread count");
    let udp_server = UdpServer::new(context_ptr.clone());
    let tcp_server = TcpServer::new(context_ptr.clone());

    // FIXME: need better way to collect server threads and join on them
    let _ = tcp_server.run(thread_count);
    match udp_server.run(thread_count) {
        Ok(handle) => handle.join().unwrap(),
        Err(e) => println!("Failed to run UDP server: {:?}", e),
    }
}
