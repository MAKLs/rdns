use super::buffer::*;
use rand::random;
use std::io::Result;
use std::net::{Ipv4Addr, Ipv6Addr};

// DNS response code
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResponseCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResponseCode {
    pub fn from_num(num: u8) -> ResponseCode {
        match num {
            1 => ResponseCode::FORMERR,
            2 => ResponseCode::SERVFAIL,
            3 => ResponseCode::NXDOMAIN,
            4 => ResponseCode::NOTIMP,
            5 => ResponseCode::REFUSED,
            _ => ResponseCode::NOERROR,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,
    NS,
    CNAME,
    MX,
    AAAA,
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(n) => n,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
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
    pub resource_entries: u16,
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
            resource_entries: 0,
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
        buffer.write(
            ((self.response as u8) << 7)
                | (self.opcode << 6)
                | ((self.authoritative_answer as u8) << 2)
                | ((self.truncated_message as u8) << 1)
                | (self.recursion_desired as u8),
        )?;

        // Write the next byte's-worth of flags
        buffer.write(
            ((self.recursion_available as u8) << 7)
                | ((self.z as u8) << 6)
                | ((self.authed_data as u8) << 5)
                | ((self.checking_disabled as u8) << 4)
                | (self.rescode as u8),
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
    pub qtype: QueryType,
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
        buffer.write_u16(1)?; // class

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
        ttl: u32,
    },
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    NS {
        domain: String,
        host: String,
        ttl: u32,
    },
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    },
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    },
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    },
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype = buffer.read_u16()?;
        let _ = buffer.read_u16()?; // ignore class
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match QueryType::from_num(qtype) {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;

                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8,
                );

                Ok(DnsRecord::A { domain, addr, ttl })
            }
            QueryType::AAAA => {
                let mask = 0xFFFF;
                let raw_addrs = (
                    buffer.read_u32()?,
                    buffer.read_u32()?,
                    buffer.read_u32()?,
                    buffer.read_u32()?,
                );
                let addr = Ipv6Addr::new(
                    ((raw_addrs.0 >> 16) & mask) as u16,
                    (raw_addrs.0 & mask) as u16,
                    ((raw_addrs.1 >> 16) & mask) as u16,
                    (raw_addrs.1 & mask) as u16,
                    ((raw_addrs.2 >> 16) & mask) as u16,
                    (raw_addrs.2 & mask) as u16,
                    ((raw_addrs.3 >> 16) & mask) as u16,
                    (raw_addrs.3 & mask) as u16,
                );

                Ok(DnsRecord::AAAA { domain, addr, ttl })
            }
            QueryType::CNAME => {
                let mut host = String::new();
                buffer.read_qname(&mut host)?;

                Ok(DnsRecord::CNAME { domain, host, ttl })
            }
            QueryType::NS => {
                let mut host = String::new();
                buffer.read_qname(&mut host)?;
                Ok(DnsRecord::NS { domain, host, ttl })
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut host = String::new();
                buffer.read_qname(&mut host)?;

                Ok(DnsRecord::MX {
                    domain,
                    priority,
                    host,
                    ttl,
                })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::UNKNOWN {
                    domain,
                    ttl,
                    data_len,
                    qtype,
                })
            }
        }
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start_pos = buffer.head();

        match *self {
            DnsRecord::A {
                ref domain,
                addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(1)?; // class
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?; // A record has 4-byte IP address

                // Write IP address
                let octets = addr.octets();
                for o in octets.iter() {
                    buffer.write(*o)?;
                }
            }
            DnsRecord::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.to_num())?;
                buffer.write_u16(1)?; // class
                buffer.write_u32(ttl)?;

                // Preserve position to rewrite size of data later
                let pos = buffer.head();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                // Rewrite size of name server
                let size = buffer.head() - (pos + 2); // 2 bytes for data length
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::CNAME.to_num())?;
                buffer.write_u16(1)?; // class
                buffer.write_u32(ttl)?;

                // Preserve position to rewrite size of data later
                let pos = buffer.head();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                // Rewrite size of canonical name
                let size = buffer.head() - (pos + 2); // 2 bytes for data length
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.to_num())?;
                buffer.write_u16(1)?; // class
                buffer.write_u32(ttl)?;

                // Preserve position to rewrite size of data later
                let pos = buffer.head();
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;

                // Rewrite size of canonical name
                let size = buffer.head() - (pos + 2); // 2 bytes for data length
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::AAAA {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.to_num())?;
                buffer.write_u16(1)?; // class
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?; // 16 byte IP address

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
            }
            DnsRecord::UNKNOWN { .. } => {
                println!("Unknown record: {:?}", self);
            }
        }

        Ok(buffer.head() - start_pos)
    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
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

        // Read in questions
        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new(String::from(""), QueryType::UNKNOWN(0));

            question.read(buffer)?;
            result.questions.push(question);
        }

        // Read in answers
        for _ in 0..result.header.answers {
            let answer = DnsRecord::read(buffer)?;
            result.answers.push(answer);
        }

        // Read in authorities
        for _ in 0..result.header.authoritative_entries {
            let authority = DnsRecord::read(buffer)?;
            result.authorities.push(authority);
        }

        // Read in resources
        for _ in 0..result.header.resource_entries {
            let resource = DnsRecord::read(buffer)?;
            result.resources.push(resource);
        }

        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        // Setup temporary buffer in case this message gets truncated
        let mut temp_buf = BytePacketBuffer::new();

        // We should have enough space so far to write the header and questions

        self.header.write(&mut temp_buf)?;
        for question in &self.questions {
            question.write(&mut temp_buf)?;
        }

        // This is where we may run out of space in the buffer... keep an eye out

        let mut record_count = self.answers.len() + self.authorities.len() + self.resources.len();
        for (i, rec) in self
            .answers
            .iter()
            .chain(self.authorities.iter())
            .chain(self.resources.iter())
            .enumerate()
        {
            match rec.write(&mut temp_buf) {
                Ok(_) => {
                    // So far so good. Increment the counters in the header
                    if i < self.answers.len() {
                        self.header.answers += 1;
                    } else if i < self.answers.len() + self.authorities.len() {
                        self.header.authoritative_entries += 1;
                    } else {
                        self.header.resource_entries += 1;
                    }
                }
                Err(e) => {
                    /* We ran out of space!
                        - Set the record count for the packet to however far we got
                        - Set the truncated bit in the header
                        - Stop trying to write to the packed buffer
                    */
                    println!("Packet {0}: {1:?}", self.header.id, e);
                    record_count = i;
                    self.header.truncated_message = true;
                    break;
                }
            }
        }

        // Now that we know we can write this packet to the buffer, do it for real

        self.header.questions = self.questions.len() as u16;
        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }

        for rec in self
            .answers
            .iter()
            .chain(self.authorities.iter())
            .chain(self.resources.iter())
            .take(record_count)
        {
            rec.write(buffer)?;
        }

        Ok(())
    }

    // Randomly choose A record from packet
    pub fn get_random_a(&self) -> Option<String> {
        if !self.answers.is_empty() {
            let idx = random::<usize>() % self.answers.len();
            let record = &self.answers[idx];
            if let DnsRecord::A { ref addr, .. } = *record {
                return Some(addr.to_string());
            }
        }

        None
    }

    pub fn get_resolved_ns(&self, qname: &str) -> Option<String> {
        let mut new_authorities: Vec<DnsRecord> = Vec::new();
        for auth in &self.authorities {
            if let DnsRecord::NS {
                ref domain,
                ref host,
                ..
            } = *auth
            {
                if !qname.ends_with(domain) {
                    continue;
                }

                // With an NS record, we MAY be able to grab its A record from the resources section
                for resource in &self.resources {
                    if let DnsRecord::A {
                        ref domain,
                        ref addr,
                        ttl,
                    } = *resource
                    {
                        if domain != host {
                            continue;
                        }

                        let rec = DnsRecord::A {
                            domain: host.clone(),
                            addr: *addr,
                            ttl,
                        };

                        new_authorities.push(rec);
                    }
                }
            }
        }

        // Choose the first authority if we have any
        if !new_authorities.is_empty() {
            if let DnsRecord::A { addr, .. } = new_authorities[0] {
                return Some(addr.to_string());
            }
        }

        None
    }

    // Just in case the name server doesn't want to make it easy and give us an A record
    pub fn get_unresolved_ns(&self, qname: &str) -> Option<String> {
        let mut new_authorities: Vec<&String> = Vec::new();
        for auth in &self.authorities {
            if let DnsRecord::NS {
                ref domain,
                ref host,
                ..
            } = *auth
            {
                if !qname.ends_with(domain) {
                    continue;
                }

                new_authorities.push(host);
            }
        }

        if !new_authorities.is_empty() {
            let idx = random::<usize>() % new_authorities.len();
            return Some(new_authorities[idx].clone());
        }

        None
    }
}
