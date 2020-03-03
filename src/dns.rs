use std::io::{Error, ErrorKind, Read, Result};
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
        self.rescode = ResponseCode::from_num((flags & 0xF) as u8); // 
        self.z = (flags >> 4) & 0xF > 0;
        self.recursion_available = (flags >> 7) > 0;
        self.recursion_desired = (flags >> 8) > 0;
        self.truncated_message = (flags >> 9) > 0;
        self.authoritative_answer = (flags >> 10) > 0;
        self.opcode = ((flags >> 11) & 0xF) as u8;
        self.response = (flags >> 15) > 0;

        // Read record count sections; each field is 16 bits
        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }
}
