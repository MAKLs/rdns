use std::net::Ipv4Addr;
use std::io::{Result};
use crate::packet::*;

// DNS response code
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResponseCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5
}

impl ResponseCode {
    pub fn from_num(num: u8) -> ResponseCode {
        match num {
            1 => ResponseCode::FORMERR,
            2 => ResponseCode::SERVFAIL,
            3 => ResponseCode::NXDOMAIN,
            4 => ResponseCode::NOTIMP,
            5 => ResponseCode::REFUSED,
            _ => ResponseCode::NOERROR
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(n) => n,
            QueryType::A => 1,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16,

    pub recursion_desired: bool,
    pub truncated_message: bool,
    pub authoritative_answer: bool,
    pub opcode: u8,
    pub response: bool,

    pub rescode: ResponseCode,
    pub checking_disabled: bool,
    pub authed_data: bool,
    pub z: bool,
    pub recursion_available: bool,

    pub questions: u16,
    pub answers: u16,
    pub authoritative_entries: u16,
    pub resource_entries: u16
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResponseCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        // Packet ID
        self.id = buffer.read_u16()?;

        /*
        Read flags from buffer at following positions
        | 0|0000| 0| 0| 0| 0| 000|  0000|
        |QR|  Op|AA|TC|RD|RA|   z| Rcode|
        */
        let flags = buffer.read_u16()?;
        self.rescode = ResponseCode::from_num((flags & 0xF) as u8);
        self.checking_disabled = (flags >> 4) & 1 > 0;
        self.authed_data = (flags >> 5) & 1 > 0;
        self.z = (flags >> 6) & 1 > 0;
        self.recursion_available = (flags >> 7) & 1 > 0;
        self.recursion_desired = (flags >> 8) & 1 > 0;
        self.truncated_message = (flags >> 9) & 1 > 0;
        self.authoritative_answer = (flags >> 10) & 1 > 0;
        self.opcode = ((flags >> 11) & 0xF) as u8;
        self.response = (flags >> 15) & 1 > 0;

        // Read record count sections; each field is 16 bits
        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        // Write packet ID
        buffer.write_u16(self.id)?;

        // Write first byte's-worth of flags
        buffer.write_u8(
            ((self.response as u8) << 7) |
            (self.opcode << 6) |
            ((self.authoritative_answer as u8) << 2) |
            ((self.truncated_message as u8) << 1) |
            (self.recursion_desired as u8)
        )?;

        // Write the next byte's-worth of flags
        buffer.write_u8(
            ((self.recursion_available as u8) << 7) |
            ((self.z as u8) << 6) |
            ((self.authed_data as u8) << 5) |
            ((self.checking_disabled as u8) << 4) |
            (self.rescode as u8)
        )?;

        // Write record counts
        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion { name, qtype }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        // Query name
        buffer.read_qname(&mut self.name)?;
        // Query type
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        // Class; ignore for now, since always 1
        let _ = buffer.read_u16()?;
        
        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_qname(&self.name)?;

        let qtype = self.qtype.to_num();
        buffer.write_u16(qtype)?;
        buffer.write_u16(1)?;   // class

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32
    },
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32
    }
}

impl DnsRecord {

    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype = buffer.read_u16()?;
        let _ = buffer.read_u16()?;     // ignore class
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match QueryType::from_num(qtype) {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                // TODO: refactor
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8
                );

                Ok(DnsRecord::A {domain, addr, ttl})
            },
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::UNKNOWN {domain, ttl, data_len, qtype })
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket> {
        // Read in header
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        // TODO: refactor reading records from buffer

        // Read in questions
        for _ in 0 .. result.header.questions {
            let mut question = DnsQuestion::new(String::from(""), QueryType::UNKNOWN(0));

            question.read(buffer)?;
            result.questions.push(question);
        }

        // Read in answers
        for _ in 0 .. result.header.answers {
            let answer = DnsRecord::read(buffer)?;
            result.answers.push(answer);
        }

        // Read in authorities
        for _ in 0 .. result.header.authoritative_entries {
            let authority = DnsRecord::read(buffer)?;
            result.authorities.push(authority);
        }

        // Read in resources
        for _ in 0 .. result.header.resource_entries {
            let resource = DnsRecord::read(buffer)?;
            result.resources.push(resource);
        }

        Ok(result)
    }
}
