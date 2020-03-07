use std::net::UdpSocket;
use crate::dns::*;
use crate::packet::*;
use std::io::{Result};

pub struct Server<'a> {
    pub addr: &'a str,
    pub port: u16,
    faddr: &'a str,
    fport: u16,
    socket: UdpSocket,
    fsocket: UdpSocket
}

impl<'a> Server<'a> {
    pub fn new(addr: &'a str, port: u16) -> Server<'a> {
        let (faddr, fport) = ("9.9.9.9", 53);
        let socket = UdpSocket::bind((addr, port)).unwrap();
        let fsocket = UdpSocket::bind((addr, 3400)).unwrap();

        Server { addr, port, socket, faddr, fport, fsocket }
    }

    fn server(&self) -> (&'a str, u16) {
        (self.faddr, self.fport)
    }

    fn lookup(&self, qname: &str, qtype: QueryType) -> Result<DnsPacket> {
        let mut packet = DnsPacket::new();

        packet.header.id = 7777;
        packet.header.questions = 1;
        packet.header.recursion_desired = true;
        packet.questions.push(DnsQuestion::new(String::from(qname), qtype));

        let mut req_buffer = BytePacketBuffer::new();
        packet.write(&mut req_buffer).unwrap();
        self.fsocket.send_to(&req_buffer.buf[0..req_buffer.head()], self.server())?;

        let mut res_buffer = BytePacketBuffer::new();
        self.fsocket.recv_from(&mut res_buffer.buf).unwrap();

        DnsPacket::from_buffer(&mut res_buffer)
    }

    pub fn run(&self) -> ! {
        // Service requests serially for now
        loop {
            // Receive a request into a buffer
            let mut req_buffer = BytePacketBuffer::new();
            let (_, src) = match self.socket.recv_from(&mut req_buffer.buf) {
                Ok(data) => data,
                Err(e) => {
                    println!("Failed to read packet: {:?}", e);
                    continue;
                },
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
                if let Ok(result) = self.lookup(&question.name, question.qtype) {
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
                Ok(_) => {},
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

            match self.socket.send_to(res_data, src) {
                Ok(_) => {},
                Err(e) => {
                    println!("Failed to send response buffer: {:?}", e);
                    continue;
                }
            }
        }
    }
}
