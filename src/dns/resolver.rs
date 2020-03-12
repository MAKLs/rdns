use super::protocol::{QueryType, DnsPacket, ResponseCode, DnsRecord};
use super::context::ServerContext;
use std::io::Result;
use std::sync::Arc;

pub enum ResolverMode {
    Forwarding { host: String, port: u16 },
    Recursive
}

impl ResolverMode {
    pub fn from_str(name: &str, server: Option<&str>) -> Option<ResolverMode> {
        match name {
            "recursive" => Some(ResolverMode::Recursive),
            "forward" => Some(ResolverMode::Forwarding {
                host: server.unwrap().to_string(),
                port : 53
            }),
            _ => None,
        }
    }
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
}

impl DnsResolver for RecursiveResolver {
    fn execute(&self, qname: &str, qtype: QueryType) -> Result<DnsPacket> {
        // For now we're always starting with *a.root-servers.net*.
        let mut ns = "198.41.0.4".to_string();

        // Loop until we resolve the lookup
        loop {
            println!(
                "\tAttempting lookup of {:?} {} with ns {}",
                qtype, qname, ns
            );
            let ns_copy = ns.clone();
            let server = (ns_copy.as_str(), 53);
            let mut response = self.context.client.send_query(qname, qtype.clone(), server, true)?;

            // If we have answers and no errors or the name server tells us no, done
            if (!response.answers.is_empty() && response.header.rescode == ResponseCode::NOERROR)
                || response.header.rescode == ResponseCode::NXDOMAIN
            {
                match qtype {
                    QueryType::A => {
                        let mut cname_responses: Vec<DnsRecord> = Vec::new();
                        for rec in &response.answers {
                            if let DnsRecord::CNAME { ref host, .. } = *rec {
                                let cname_resp = self.resolve(&host, QueryType::A, true)?;
                                println!("Resolved CNAME: {:?}", &host);
                                response.header.rescode = cname_resp.header.rescode;

                                for a_rec in cname_resp.answers {
                                    cname_responses.push(a_rec);
                                    response.header.answers += 1;
                                }
                            };
                        }
                        response.answers.extend(cname_responses);
                    }
                    _ => {}
                }

                return Ok(response);
            }

            // Otherwise, find the next name server
            // First, check if we have the next NS's A record
            if let Some(new_ns) = response.get_resolved_ns(qname) {
                ns = new_ns;
                continue;
            }

            // If not, resolve the IP of the NS
            let new_ns_name = match response.get_unresolved_ns(qname) {
                Some(name) => name,
                None => return Ok(response),
            };

            // Now, we have to recursively resolve this NS's IP address
            let recursive_response = self.resolve(&new_ns_name, QueryType::A, true)?;
            if let Some(new_ns) = recursive_response.get_random_a() {
                ns = new_ns;
            } else {
                return Ok(response);
            }
        }
    }
}