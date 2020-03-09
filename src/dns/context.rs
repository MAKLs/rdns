use super::network::NetworkClient;
use super::resolver::{ResolverMode, DnsResolver, ForwardResolver};
use std::boxed::Box;
use std::sync::Arc;

pub struct ServerContext {
    pub client: NetworkClient,
    pub dns_port: u16,
    resolver_mode: ResolverMode,
    allow_recursion: bool
}

impl ServerContext {
    pub fn new() -> ServerContext {
        ServerContext {
            client: NetworkClient::new(34521),
            dns_port: 2053,
            resolver_mode: ResolverMode::Forwarding { host: "9.9.9.9".to_string(), port: 53 },    // FIXME: read from command line or config file
            allow_recursion: true
        }
    }

    pub fn get_resolver(&self, context_ptr: Arc<ServerContext>) -> Box<dyn DnsResolver> {
        match self.resolver_mode {
            ResolverMode::Forwarding { ref host, port } => Box::new(ForwardResolver::new((host.clone(), port), context_ptr)),
            _ => unimplemented!()
        }
    }
}