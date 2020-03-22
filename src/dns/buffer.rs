use std::io::{Error, ErrorKind, Result};

// Maximum size of DNS packet
const MAX_SIZE: usize = 512;
// Maximum size of label
const MAX_LABEL_LEN: usize = 63;

pub trait ByteBuffer {
    // Get current position of the cursor in the buffer.
    fn head(&self) -> usize;

    // Manipulating head of buffer

    fn step(&mut self, steps: usize) -> Result<()>;

    fn seek(&mut self, offset: usize) -> Result<()>;

    // Basic reading from buffer

    fn read(&mut self) -> Result<u8>;

    fn read_u16(&mut self) -> Result<u16> {
        let data = (self.read()? as u16) << 8 | self.read()? as u16;

        Ok(data)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let data = (self.read_u16()? as u32) << 16 | self.read_u16()? as u32;

        Ok(data)
    }

    // Basic writing to buffer

    fn write(&mut self, data: u8) -> Result<()>;

    fn write_u16(&mut self, data: u16) -> Result<()> {
        // Write high byte
        self.write((data >> 8) as u8)?;
        // Write low byte
        self.write((data & 0xFF) as u8)?;

        Ok(())
    }

    fn write_u32(&mut self, data: u32) -> Result<()> {
        // Write two high bytes
        self.write_u16((data >> 16) as u16)?;
        // Write two low bytes
        self.write_u16((data & 0xFFFF) as u16)?;

        Ok(())
    }

    // Reading from buffer without mutating buffer's head

    fn get(&self, offset: usize) -> Result<u8>;

    fn get_range(&self, offset: usize, len: usize) -> Result<&[u8]>;

    // Writing to buffer without mutating buffer's head

    fn set(&mut self, offset: usize, data: u8) -> Result<()>;

    fn set_u16(&mut self, offset: usize, data: u16) -> Result<()> {
        // Set high byte
        self.set(offset, (data >> 8) as u8)?;
        // Set low byte
        self.set(offset + 1, (data & 0xFF) as u8)?;

        Ok(())
    }

    // Methods for interacting with domain names

    fn read_qname(&mut self, qname: &mut String) -> Result<()> {
        // To handle jumps keep track of head offset locally
        let mut pos = self.head();

        // track whether we've encountered a jump
        let mut jumped = false;

        // Delimiter between labels in name. For first iteration, keep empty.
        // Next iterations will use '.'
        let mut delim = "";
        loop {
            // Beginning of label, so grab length byte
            let label_len = self.get(pos)?;

            // If two most significant bits are set, we need to jump
            if (label_len & 0xC0) == 0xC0 {
                // Move the head past the length byte and jump byte
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // Read another byte, calculate offset and jump
                let jump_byte = self.get(pos + 1)? as u16;
                let offset = (((label_len as u16) ^ 0xC0) << 8) | jump_byte;
                pos = offset as usize;

                // We jumped
                jumped = true;
            }
            // No-jump scenario, where a single label is read
            else {
                // Move one byte past length byte
                pos += 1;

                // Domain names are terminated by an empty byte
                if label_len == 0 {
                    break;
                }

                // Apppend delimiter to output buffer
                qname.push_str(delim);

                // Extract ASCII bytes for the label and append to output buffer
                let str_buffer = self.get_range(pos, label_len as usize)?;
                qname.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                // Move forward in packet buffer by length of label
                pos += label_len as usize;
            }
        }

        // If we jumped, no need to change buffer position
        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }

    fn write_qname(&mut self, qname: &str) -> Result<()> {
        let labels = qname.split('.').collect::<Vec<&str>>();

        for label in labels {
            // Check label length
            let len = label.len();
            if len > MAX_LABEL_LEN {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("Label exceeds maximum length: {0}", MAX_LABEL_LEN),
                ));
            }

            // Write the length of the label and then the label
            self.write(len as u8)?;
            for label_byte in label.as_bytes() {
                self.write(*label_byte)?;
            }
        }

        // Write null byte to terminate qname
        self.write(0)?;

        Ok(())
    }
}

pub struct BytePacketBuffer {
    pub buf: [u8; MAX_SIZE], // buffer data
    pub head: usize,         // byte-offset in packet
}

impl BytePacketBuffer {
    // Fresh buffer
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; MAX_SIZE],
            head: 0,
        }
    }
}

impl ByteBuffer for BytePacketBuffer {

    fn head(&self) -> usize {
        self.head
    }

    fn step(&mut self, steps: usize) -> Result<()> {
        self.head += steps;

        Ok(())
    }

    fn seek(&mut self, offset: usize) -> Result<()> {
        self.head = offset;

        Ok(())
    }

    fn read(&mut self) -> Result<u8> {
        if self.head >= MAX_SIZE {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }
        let data = self.buf[self.head];
        self.step(1)?;

        Ok(data)
    }

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

        Ok(&self.buf[start..start + len])
    }

    fn write(&mut self, val: u8) -> Result<()> {
        if self.head() >= MAX_SIZE {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }
        self.buf[self.head()] = val;
        self.step(1)?;

        Ok(())
    }

    fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        self.buf[pos] = val;

        Ok(())
    }
}

pub struct ExtendingBuffer {
    pub buf: Vec<u8>,
    head: usize
}

impl ExtendingBuffer {
    pub fn new() -> ExtendingBuffer {
        ExtendingBuffer {
            buf: Vec::with_capacity(MAX_SIZE),  // TODO: decide sane capacity for performance
            head: 0
        }
    }
}

impl ByteBuffer for ExtendingBuffer {
    fn head(&self) -> usize {
        self.head
    }

    fn step(&mut self, steps: usize) -> Result<()> {
        self.head += steps;

        Ok(())
    }

    fn seek(&mut self, offset: usize) -> Result<()> {
        self.head = offset;

        Ok(())
    }

    fn read(&mut self) -> Result<u8> {
        let data = self.buf[self.head()];
        self.step(1)?;

        Ok(data)
    }

    fn write(&mut self, data: u8) -> Result<()> {
        self.buf.push(data);
        self.step(1)?;

        Ok(())
    }

    fn get(&self, offset: usize) -> Result<u8> {
        if self.head() >= self.buf.len() {
            return Err(Error::new(ErrorKind::InvalidInput, "Attempted read beyond buffer"));
        }

        let data = self.buf[offset];

        Ok(data)
    }

    fn get_range(&self, offset: usize, len: usize) -> Result<&[u8]> {
        if offset + len >= self.buf.len() {
            return Err(Error::new(ErrorKind::InvalidInput, "Attempted read beyond buffer"));
        }

        let data = &self.buf[offset..len];

        Ok(data)
    }

    fn set(&mut self, offset: usize, data: u8) -> Result<()> {
        if self.head() >= self.buf.len() {
            return Err(Error::new(ErrorKind::InvalidInput, "Attempted write beyond buffer"));
        }

        self.buf[offset] = data;

        Ok(())
    }
}