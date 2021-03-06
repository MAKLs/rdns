use super::network::NetworkClient;
use super::resolver::{DnsResolver, ForwardResolver, RecursiveResolver, ResolverMode};
use std::boxed::Box;
use std::sync::Arc;

pub struct ServerContext {
    pub client: NetworkClient,
    pub dns_port: u16,
    resolver_mode: ResolverMode,
    pub allow_recursion: bool,
}

impl ServerContext {
    pub fn new() -> ServerContext {
        ServerContext {
            client: NetworkClient::new(34521),
            dns_port: 2053,
            resolver_mode: ResolverMode::Forwarding {
                host: "0.0.0.0".to_string(),
                port: 53,
            },
            allow_recursion: true,
        }
    }

    pub fn set_resolver_mode(&mut self, mode: ResolverMode) {
        self.resolver_mode = mode;
    }

    pub fn get_resolver(&self, context_ptr: Arc<ServerContext>) -> Box<dyn DnsResolver> {
        match self.resolver_mode {
            ResolverMode::Forwarding { ref host, port } => {
                Box::new(ForwardResolver::new((host.clone(), port), context_ptr))
            }
            ResolverMode::Recursive => Box::new(RecursiveResolver::new(context_ptr)),
        }
    }
}
