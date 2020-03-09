mod dns;
use dns::{context::ServerContext, server::Server};
use std::sync::Arc;

fn main() {
    println!("Starting rDNS\n");
    let context = Arc::new(ServerContext::new());
    let server = Server::new(context);
    server.run();
}
