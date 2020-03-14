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
