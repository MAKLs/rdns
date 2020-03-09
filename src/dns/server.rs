use super::buffer::*;
use super::context::ServerContext;
use super::network::NetworkClient;
use super::protocol::*;
use super::resolver::{DnsResolver, ForwardResolver};
use rand::random;
use std::boxed::Box;
use std::io::Result;
use std::net::UdpSocket;
use std::sync::Arc;

pub struct Server {
    context: Arc<ServerContext>,
}

impl Server {
    pub fn new(context: Arc<ServerContext>) -> Server {
        Server { context }
    }

    fn lookup(&self, qname: &str, qtype: QueryType, server: (&str, u16)) -> Result<DnsPacket> {
        let socket = UdpSocket::bind(("0.0.0.0", 3400)).unwrap();
        let mut packet = DnsPacket::new();

        packet.header.id = random::<u16>();
        packet.header.questions = 1;
        packet.header.recursion_desired = true;
        packet
            .questions
            .push(DnsQuestion::new(String::from(qname), qtype));

        let mut req_buffer = BytePacketBuffer::new();
        packet.write(&mut req_buffer).unwrap();
        socket.send_to(&req_buffer.buf[0..req_buffer.head()], server)?;

        let mut res_buffer = BytePacketBuffer::new();
        socket.recv_from(&mut res_buffer.buf).unwrap();

        DnsPacket::from_buffer(&mut res_buffer)
    }

    fn recursive_lookup(&self, qname: &str, qtype: QueryType) -> Result<DnsPacket> {
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
            let mut response = self.lookup(qname, qtype.clone(), server)?;

            // If we have answers and no errors or the name server tells us no, done
            if (!response.answers.is_empty() && response.header.rescode == ResponseCode::NOERROR)
                || response.header.rescode == ResponseCode::NXDOMAIN
            {
                match qtype {
                    QueryType::A => {
                        let mut cname_responses: Vec<DnsRecord> = Vec::new();
                        for rec in &response.answers {
                            if let DnsRecord::CNAME { ref host, .. } = *rec {
                                let cname_resp = self.recursive_lookup(&host, QueryType::A)?;
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
            let recursive_response = self.recursive_lookup(&new_ns_name, QueryType::A)?;
            if let Some(new_ns) = recursive_response.get_random_a() {
                ns = new_ns;
            } else {
                return Ok(response);
            }
        }
    }

    pub fn run(&self) -> ! {
        let socket = UdpSocket::bind(("0.0.0.0", self.context.dns_port)).unwrap();
        let resolver = self.context.get_resolver(self.context.clone());

        // Service requests serially for now
        loop {
            // Receive a request into a buffer
            let mut req_buffer = BytePacketBuffer::new();
            let (_, src) = match socket.recv_from(&mut req_buffer.buf) {
                Ok(data) => data,
                Err(e) => {
                    println!("Failed to read packet: {:?}", e);
                    continue;
                }
            };

            // Read DNS packet from buffer
            let request = match DnsPacket::from_buffer(&mut req_buffer) {
                Ok(packet) => packet,
                Err(e) => {
                    println!("Failed to parse DNS packet: {:?}", e);
                    continue;
                }
            };

            // Prepare response packet
            let mut response = DnsPacket::new();
            response.header.id = request.header.id; // question and answer must have same id
            response.header.recursion_desired = true;
            response.header.recursion_available = true;
            response.header.response = true;

            // If the request has no questions, return a FORMERR
            if request.questions.is_empty() {
                response.header.rescode = ResponseCode::FORMERR;
            } else {
                let question = &request.questions[0];
                println!("Received query: {:?}", question);

                // Now, forward the request to the downstream server
                if let Ok(result) = resolver.resolve(&question.name, question.qtype, true) {
                    response.questions.push(question.clone());
                    response.header.rescode = result.header.rescode;
                    for rec in result.answers {
                        println!("Answers: {:?}", rec);
                        response.answers.push(rec);
                    }
                    for rec in result.authorities {
                        println!("Authority: {:?}", rec);
                        response.authorities.push(rec);
                    }
                    for rec in result.resources {
                        println!("Resource: {:?}", rec);
                        response.resources.push(rec);
                    }
                } else {
                    response.header.rescode = ResponseCode::SERVFAIL;
                }
            }

            // Finally, write the response to a buffer and return to client
            let mut res_buffer = BytePacketBuffer::new();
            match response.write(&mut res_buffer) {
                Ok(_) => {}
                Err(e) => {
                    println!("Failed to write response packet to buffer: {:?}", e);
                    continue;
                }
            };

            let res_len = res_buffer.head();
            let res_data = match res_buffer.get_range(0, res_len) {
                Ok(result) => result,
                Err(e) => {
                    println!("Failed to read response buffer: {:?}", e);
                    continue;
                }
            };

            match socket.send_to(res_data, src) {
                Ok(_) => {}
                Err(e) => {
                    println!("Failed to send response buffer: {:?}", e);
                    continue;
                }
            }
        }
    }
}
