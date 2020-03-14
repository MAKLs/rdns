use super::protocol::{DnsPacket, QueryType, DnsQuestion};
use super::buffer::BytePacketBuffer;
use std::io::{Result, Error, ErrorKind};
use std::net::UdpSocket;
use std::sync::atomic::{AtomicU16, Ordering};

pub struct NetworkClient {
    socket: UdpSocket,
    pid_seq: AtomicU16
}

impl NetworkClient {
    pub fn new(port: u16) -> NetworkClient {
        NetworkClient {
            pid_seq: AtomicU16::new(0),
            socket: UdpSocket::bind(("0.0.0.0", port)).unwrap()
        }
    }

    fn send_tcp_query(&self, qname: &str, qtype: QueryType, server: (&str, u16), recursive: bool) -> Result<DnsPacket> {
        println!("Would query {} over TCP", qname);
        unimplemented!();
    }

    fn send_udp_query(&self, qname: &str, qtype: QueryType, server: (&str, u16), recursive: bool) -> Result<DnsPacket> {
        let mut packet = DnsPacket::new();

        packet.header.id = self.pid_seq.fetch_add(1, Ordering::SeqCst);
        packet.header.questions = 1;
        packet.header.recursion_desired = recursive;
        packet
            .questions
            .push(DnsQuestion::new(String::from(qname), qtype));

        let mut req_buffer = BytePacketBuffer::new();
        packet.write(&mut req_buffer).unwrap();
        self.socket.send_to(&req_buffer.buf[0..req_buffer.head()], server)?;

        let mut res_buffer = BytePacketBuffer::new();
        self.socket.recv_from(&mut res_buffer.buf).unwrap();

        DnsPacket::from_buffer(&mut res_buffer)
    }

    pub fn send_query(&self, qname: &str, qtype: QueryType, server: (&str, u16), recursive: bool) -> Result<DnsPacket> {
        let packet = self.send_udp_query(qname, qtype, server, recursive)?;

        if !packet.header.truncated_message {
            return Ok(packet);
        }

        self.send_tcp_query(qname, qtype, server, recursive)
    }
}