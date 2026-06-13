use crate::error::{Result, dns_error};

pub const DNS_PACKET_SIZE: usize = 512;

pub struct BytePacketBuffer {
    pub buf: [u8; DNS_PACKET_SIZE],
    pub pos: usize,
}

impl BytePacketBuffer {
    pub fn new() -> Self {
        Self {
            buf: [0; DNS_PACKET_SIZE],
            pos: 0,
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn step(&mut self, steps: usize) -> Result<()> {
        self.seek(self.pos + steps)
    }

    pub fn seek(&mut self, pos: usize) -> Result<()> {
        if pos > DNS_PACKET_SIZE {
            return Err(dns_error("End of buffer"));
        }
        self.pos = pos;
        Ok(())
    }

    pub fn read(&mut self) -> Result<u8> {
        if self.pos >= DNS_PACKET_SIZE {
            return Err(dns_error("End of buffer"));
        }

        let result = self.buf[self.pos];
        self.pos += 1;

        Ok(result)
    }

    pub fn get(&self, pos: usize) -> Result<u8> {
        if pos >= DNS_PACKET_SIZE {
            return Err(dns_error("End of buffer"));
        }

        Ok(self.buf[pos])
    }

    pub fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len > DNS_PACKET_SIZE {
            return Err(dns_error("End of buffer"));
        }

        Ok(&self.buf[start..start + len])
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        Ok(((self.read()? as u16) << 8) | self.read()? as u16)
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        Ok(((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | self.read()? as u32)
    }

    pub fn read_qname(&mut self, out: &mut String) -> Result<()> {
        let mut pos = self.pos();
        let mut jumped = false;
        let mut jumps_performed = 0;
        let mut delimiter = "";

        loop {
            if jumps_performed > 5 {
                return Err(dns_error("DNS label compression jump limit exceeded"));
            }

            let len = self.get(pos)?;

            if (len & 0xC0) == 0xC0 {
                if !jumped {
                    self.seek(pos + 2)?;
                }

                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;
                jumped = true;
                jumps_performed += 1;
                continue;
            }

            pos += 1;

            if len == 0 {
                break;
            }

            out.push_str(delimiter);

            let str_buffer = self.get_range(pos, len as usize)?;
            out.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

            delimiter = ".";
            pos += len as usize;
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }

    pub fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= DNS_PACKET_SIZE {
            return Err(dns_error("End of buffer"));
        }

        self.buf[self.pos] = val;
        self.pos += 1;

        Ok(())
    }

    pub fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)
    }

    pub fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;
        Ok(())
    }

    pub fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write((val & 0xFF) as u8)?;
        Ok(())
    }

    pub fn write_qname(&mut self, qname: &str) -> Result<()> {
        let normalized = qname.trim_end_matches('.');

        if normalized.is_empty() {
            self.write_u8(0)?;
            return Ok(());
        }

        for label in normalized.split('.') {
            let len = label.len();

            if len > 0x3f {
                return Err(dns_error("Single DNS label exceeds 63 bytes"));
            }

            self.write_u8(len as u8)?;

            for byte in label.as_bytes() {
                self.write_u8(*byte)?;
            }
        }

        self.write_u8(0)?;
        Ok(())
    }

    pub fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        if pos >= DNS_PACKET_SIZE {
            return Err(dns_error("End of buffer"));
        }

        self.buf[pos] = val;
        Ok(())
    }

    pub fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;
        Ok(())
    }
}

impl Default for BytePacketBuffer {
    fn default() -> Self {
        Self::new()
    }
}
