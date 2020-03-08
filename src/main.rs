mod dns;
use dns::server::Server;

fn main() {
    println!("Starting rDNS\n");
    let server = Server::new("0.0.0.0", 2053);
    server.run();
}
