extern crate clap;
use clap::{Arg, App};
mod dns;
use dns::{context::ServerContext, server::Server, resolver::ResolverMode};
use std::sync::Arc;

fn main() {
    // Get command line arguments
    let matches = App::new("rDNS")
                          .author("MAKLs")
                          .about("Recursive DNS resolver")
                          .arg(Arg::with_name("mode")
                                .short("m")
                                .long("mode")
                                .value_name("RESOLVER MODE")
                                .possible_values(&["recursive", "forward"])
                                .default_value("recursive"))
                          .arg(Arg::with_name("downstream_server")
                                .short("s")
                                .long("server")
                                .value_name("DOWNSTREAM DNS SERVER")
                                .required_if("mode", "forward"))
                          .get_matches();
    println!("Starting rDNS\n");

    // Prepare server context
    let mut context = ServerContext::new();
    let resolver_mode = ResolverMode::from_str(matches.value_of("mode").unwrap(), matches.value_of("downstream_server"));
    if let Some(mode) = resolver_mode {
        context.set_resolver_mode(mode);
    } else {
        context.set_resolver_mode(ResolverMode::Recursive);
    }

    // Run server
    let server = Server::new(Arc::new(context));
    server.run();
}
