use super::protocol::{QueryType, DnsPacket, ResponseCode};
use super::context::ServerContext;
use std::io::Result;
use std::sync::Arc;

pub enum ResolverMode {
    Forwarding { host: String, port: u16 },
    Recursive
}

pub trait DnsResolver {
    fn resolve(&self, qname: &str, qtype: QueryType, recursive: bool) -> Result<DnsPacket> {
        // If query type is unknown, then we haven't implemented it yet
        if let QueryType::UNKNOWN(_) = qtype {
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResponseCode::NOTIMP;
            return Ok(packet);
        }

        // TODO: once implemented, check local authority for record

        // TODO: once implemented, check cache for record

        // Finally, execute resolution using a name server or downstream server
        self.execute(qname, qtype)
    }

    fn execute(&self, qname: &str, qtype: QueryType) -> Result<DnsPacket>;
}

pub struct ForwardResolver {
    server: (String, u16),
    context: Arc<ServerContext>
}

impl ForwardResolver {
    pub fn new(server: (String, u16), context: Arc<ServerContext>) -> ForwardResolver {
        ForwardResolver { server, context }
    }
}

impl DnsResolver for ForwardResolver {
    fn execute(&self, qname: &str, qtype: QueryType) -> Result<DnsPacket> {
        let (ref host, port) = &self.server;
        let result = self.context.client.send_query(qname, qtype, (host, *port), true);

        // TODO: store the result in the DNS record cache

        result
    }
}

pub struct RecursiveResolver {
    context: Arc<ServerContext>
}

impl RecursiveResolver {
    pub fn new(context: Arc<ServerContext>) -> RecursiveResolver {
        RecursiveResolver { context }
    }

    pub fn execute(&self, qname: &str, qtype: QueryType) -> Result<DnsPacket> {
        unimplemented!();
    }
}