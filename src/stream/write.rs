use crate::BLOCK_DATA_SIZE;
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
        if self.inner_buf.is_empty() {
            return Ok(());
        }

        let encrypted_block = self.encrypter.encrypt_block(self.block_id, &self.inner_buf);
        if self.block_id == 0 {
            self.inner.write(&self.encrypter.get_file_header())?;
        }
        self.inner.write(&encrypted_block)?;
        self.inner_buf.clear();
        Ok(())
    }
}

impl<W: Write> Write for EncryptedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        for byte in buf {
            if self.inner_buf.len() == BLOCK_DATA_SIZE {
                let mut encrypted = Vec::new();

                if self.block_id == 0 {
                    encrypted.extend(self.encrypter.get_file_header());
                }
                encrypted.extend(self.encrypter.encrypt_block(self.block_id, &self.inner_buf));

                self.inner.write(&encrypted)?;
                self.block_id += 1;
                self.inner_buf.clear();
            }

            self.inner_buf.push(*byte);
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
