mod dns;
use dns::{context::ServerContext, server::Server, resolver::ResolverMode};
use std::sync::Arc;

fn main() {
    println!("Starting rDNS\n");
    let mut context = ServerContext::new();
    context.set_resolver_mode(ResolverMode::Recursive);
    let server = Server::new(Arc::new(context));
    server.run();
}
