use super::buffer::{ByteBuffer, BytePacketBuffer, ExtendingBuffer, VariableBuffer};
use super::protocol::{DnsPacket, DnsQuestion, QueryType};
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};

pub struct NetworkClient {
    socket: UdpSocket,
    pid_seq: AtomicU16,
}

impl NetworkClient {
    pub fn new(port: u16) -> NetworkClient {
        NetworkClient {
            pid_seq: AtomicU16::new(0),
            socket: UdpSocket::bind(("0.0.0.0", port)).unwrap(),
        }
    }

    fn send_tcp_query(
        &self,
        qname: &str,
        qtype: QueryType,
        server: (&str, u16),
        recursive: bool,
    ) -> Result<DnsPacket> {
        // Set up connection to downstream server
        let mut stream = TcpStream::connect(&server)?;

        // Prepare question packet to send downstream
        let mut packet = DnsPacket::new();
        packet.header.id = self.pid_seq.fetch_add(1, Ordering::SeqCst);
        packet.header.questions = 1;
        packet.header.recursion_desired = recursive;
        packet
            .questions
            .push(DnsQuestion::new(String::from(qname), qtype));

        // Write question into buffer and send request
        let mut req_buffer = BytePacketBuffer::new();
        let data_len = packet.write(&mut req_buffer).unwrap();
        let mut len_buffer = [0; 2];
        len_buffer[0] = (data_len >> 8) as u8;
        len_buffer[1] = (data_len & 0xFF) as u8;
        stream.write(&len_buffer)?;
        stream.write(&req_buffer.buf[0..req_buffer.head()])?;

        // Read the response
        let mut len_buffer = [0; 2];
        stream.read(&mut len_buffer)?;
        let buf_len = ((len_buffer[0] as u16) << 8) | (len_buffer[1] as u16);
        let mut res_buffer = VariableBuffer::new(buf_len as usize);
        stream.read(&mut res_buffer.buf).unwrap();

        DnsPacket::from_buffer(&mut res_buffer)
    }

    fn send_udp_query(
        &self,
        qname: &str,
        qtype: QueryType,
        server: (&str, u16),
        recursive: bool,
    ) -> Result<DnsPacket> {
        let mut packet = DnsPacket::new();

        packet.header.id = self.pid_seq.fetch_add(1, Ordering::SeqCst);
        packet.header.questions = 1;
        packet.header.recursion_desired = recursive;
        packet
            .questions
            .push(DnsQuestion::new(String::from(qname), qtype));

        let mut req_buffer = BytePacketBuffer::new();
        packet.write(&mut req_buffer).unwrap();
        self.socket
            .send_to(&req_buffer.buf[0..req_buffer.head()], server)?;

        let mut res_buffer = BytePacketBuffer::new();
        self.socket.recv_from(&mut res_buffer.buf).unwrap();

        DnsPacket::from_buffer(&mut res_buffer)
    }

    pub fn send_query(
        &self,
        qname: &str,
        qtype: QueryType,
        server: (&str, u16),
        recursive: bool,
    ) -> Result<DnsPacket> {
        let packet = self.send_udp_query(qname, qtype, server, recursive)?;

        if !packet.header.truncated_message {
            return Ok(packet);
        }

        self.send_tcp_query(qname, qtype, server, recursive)
    }
}
