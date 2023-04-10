use crate::BLOCK_SIZE;
use crate::{cipher::Cipher, decrypter::Decrypter};
use crate::{FILE_HEADER_SIZE, FILE_MAGIC};
use std::io::Result;
use std::io::{Error, ErrorKind, Read};

pub struct EncryptedReader<R: Read> {
    decrypter: Decrypter,
    block_id: u64,
    inner: R,
    inner_buf: Vec<u8>,
}

impl<R: Read> EncryptedReader<R> {
    pub fn new(mut inner: R, password: String, salt: String) -> Result<Self> {
        let mut header_buf = [0u8; FILE_HEADER_SIZE];
        inner.read_exact(&mut header_buf)?;

        if &header_buf[0..FILE_MAGIC.len()] != FILE_MAGIC {
            return Err(Error::new(ErrorKind::Other, "Bad Rclone header"));
        }

        let cipher = Cipher::new(password, salt).unwrap();
        let decrypter = Decrypter::new(&cipher.get_file_key(), &header_buf).unwrap();

        Ok(Self {
            decrypter,
            block_id: 0,
            inner,
            inner_buf: vec![],
        })
    }

    fn next_chunk(&mut self) -> Result<()> {
        let mut buffer = vec![0; BLOCK_SIZE];
        let read = self.inner.read(&mut buffer)?;
        buffer.truncate(read);

        if read == 0 {
            return Err(Error::new(ErrorKind::Other, "No more data to read"));
        }

        let decrypted = self
            .decrypter
            .decrypt_block(self.block_id, &buffer)
            .unwrap();

        self.inner_buf = decrypted;

        if read == BLOCK_SIZE {
            self.block_id += 1;
        }
        Ok(())
    }
}

impl<R: Read> Read for EncryptedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut index = 0;

        loop {
            if self.inner_buf.is_empty() {
                if self.next_chunk().is_err() {
                    break;
                }
            }
            let Some(ptr) = buf.get_mut(index) else {
                break;
            };
            *ptr = self.inner_buf.remove(0);

            index += 1;
        }

        if index == 0 {
            return Ok(0);
        }

        Ok(index)
    }
}
