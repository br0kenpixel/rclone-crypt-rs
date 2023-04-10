use crate::BLOCK_SIZE;
use crate::{cipher::Cipher, encrypter::Encrypter};
use std::io::Result;
use std::io::Write;

pub struct EncryptedWriter<W: Write> {
    encrypter: Encrypter,
    block_id: u64,
    inner: W,
    inner_buf: Vec<u8>,
}

impl<W: Write> EncryptedWriter<W> {
    pub fn new(inner: W, password: String, salt: String) -> Self {
        let cipher = Cipher::new(password, salt).unwrap();
        let encrypter = Encrypter::new(&cipher.get_file_key()).unwrap();

        Self {
            encrypter,
            block_id: 0,
            inner,
            inner_buf: vec![],
        }
    }

    fn finish(&mut self) -> Result<()> {
        let encrypted_block = self.encrypter.encrypt_block(self.block_id, &self.inner_buf);
        if self.block_id == 0 {
            self.inner.write(&self.encrypter.get_file_header())?;
        }
        self.inner.write(&encrypted_block)?;
        Ok(())
    }
}

impl<W: Write> Write for EncryptedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        for byte in buf {
            self.inner_buf.push(*byte);
            if self.inner_buf.len() == BLOCK_SIZE {
                let encrypted_block = self.encrypter.encrypt_block(self.block_id, &self.inner_buf);
                if self.block_id == 0 {
                    self.inner.write(&self.encrypter.get_file_header())?;
                }
                self.inner.write(&encrypted_block)?;
                self.inner_buf.clear();
            }
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }
}

impl<W: Write> Drop for EncryptedWriter<W> {
    fn drop(&mut self) {
        self.finish().unwrap();
    }
}
