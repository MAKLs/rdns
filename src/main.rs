mod dns;
mod packet;
use packet::BytePacketBuffer;
use dns::{QueryType, DnsPacket, DnsQuestion};
use std::net::UdpSocket;

fn main() {
    // Perform A query for rust-lang.org
    let qname = "yahoo.com";
    let qtype = QueryType::MX;

    // Use Quad9 server
    let server = ("9.9.9.9", 53);

    // Bind UDP socket to port
    let socket = UdpSocket::bind(("0.0.0.0", 3000)).unwrap();

    // Build query packet
    let mut packet = DnsPacket::new();

    packet.header.id = 7777;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet.questions.push(DnsQuestion::new(qname.to_string(), qtype));

    // Write packet to buffer and send it off
    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer).unwrap();
    socket.send_to(&req_buffer.buf[0..req_buffer.head()], server).unwrap();

    // Prepare buffer for response
    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf).unwrap();

    // Load the response buffer into a packet and display
    let res_packet = DnsPacket::from_buffer(&mut res_buffer).unwrap();
    println!("{:#?}", res_packet.header);

    for question in res_packet.questions.iter() {
        println!("{:#?}", question);
    }
    for rec in res_packet.answers.iter() {
        println!("{:#?}", rec);
    }
    for rec in res_packet.authorities.iter() {
        println!("{:#?}", rec);
    }
    for rec in res_packet.resources.iter() {
        println!("{:#?}", rec);
    }
}
