use std::io::{Error, ErrorKind, Result};

// Maximum size of DNS packet
const MAX_SIZE: usize = 512;
// Maximum size of label
const MAX_LABEL_LEN: usize = 63;

pub struct BytePacketBuffer {
    pub buf: [u8; MAX_SIZE],    // buffer data
    pub head: usize             // byte-offset in packet
}

impl BytePacketBuffer {

    // Fresh buffer
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; MAX_SIZE],
            head: 0
        }
    }

    pub fn head(&self) -> usize {
        self.head
    }

    // Move head along buffer
    pub fn step(&mut self, steps: usize) -> Result<()> {
        self.head += steps;

        Ok(())
    }

    // Seek the buffer head to some offset
    fn seek(&mut self, offset: usize) -> Result<()> {
        self.head = offset;

        Ok(())
    }

    // Read single byte and move along buffer
    pub fn read(&mut self) -> Result<u8> {
        if self.head >= MAX_SIZE {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }
        let data = self.buf[self.head];
        self.step(1)?;

        Ok(data)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        let data = (self.read()? as u16) << 8 | self.read()? as u16;

        Ok(data)
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        let data = (self.read()? as u32) << 24 |
            (self.read()? as u32) << 16 |
            (self.read()? as u32) << 8 |
            (self.read()? as u32);

        Ok(data)
    }

    // Methods for reading data from buffer without mutating buffer state

    fn get(&self, offset: usize) -> Result<u8> {
        if offset >= MAX_SIZE {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }
        
        Ok(self.buf[offset])
    }

    fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= MAX_SIZE {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }

        Ok(&self.buf[start..start+len])
    }

    pub fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        // To handle jumps keep track of head offset locally
        let mut pos = self.head();

        // track whether we've encountered a jump
        let mut jumped = false;

        // Delimiter between labels in name. For first iteration, keep empty.
        // Next iterations will use '.'
        let mut delim = "";
        loop {
            // Beginning of label, so grab length byte
            let len = self.get(pos)?;

            // If two most significant bytes are set, we need to jump
            if (len & 0xC0) == 0xC0 {
                // Move the head past the label since it contains no additional information
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // Read another byte, calculate offset and jump
                let jump_byte = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | jump_byte;
                pos = offset as usize;

                // We jumped
                jumped = true;
            }
            // No-jump scenario, where a single label is read
            else {
                // Move one byte past length byte
                pos += 1;

                // Domain names are terminated by an empty label
                if len == 0 {
                    break;
                }

                // Apppend delimiter to output buffer
                outstr.push_str(delim);

                // Extract ASCII bytes for the label and append to output buffer
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                // Move forward in packet buffer by length of label
                pos += len as usize;
            }
        }

        // If we jumped, no need to change buffer position
        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }

    fn write(&mut self, val: u8) -> Result<()> {
        if self.head() >= MAX_SIZE {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }
        self.buf[self.head()] = val;
        self.step(1)?;
        
        Ok(())
    }

    pub fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)?;

        Ok(())
    }

    pub fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    pub fn write_u32(&mut self, val: u32) -> Result<()> {
        let mask = 0xFF;
        self.write(((val >> 24) & mask) as u8)?;
        self.write(((val >> 16) & mask) as u8)?;
        self.write(((val >> 8) & mask) as u8)?;
        self.write(((val >> 0) & mask) as u8)?;

        Ok(())
    }

    pub fn write_qname(&mut self, qname: &str) -> Result<()> {
        let labels = qname.split('.').collect::<Vec<&str>>();

        for label in labels {
            // Check label length
            let len = label.len();
            if len > MAX_LABEL_LEN {
                return Err(Error::new(ErrorKind::InvalidInput, format!("Label exceeds maximum length: {0}", MAX_LABEL_LEN)));
            }

            // Write the length of the label and then the label
            self.write_u8(len as u8)?;
            for label_byte in label.as_bytes() {
                self.write_u8(*label_byte)?;
            }
        }

        // Write null byte to terminate qname
        self.write_u8(0)?;

        Ok(())
    }
}
