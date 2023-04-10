use crate::BLOCK_DATA_SIZE;
use crate::{cipher::Cipher, encrypter::Encrypter};
use std::io::Result;
use std::io::Write;

/// A writer which automatically encrypts data from an inner reader.
///
/// Seeking is not supported yet.
///
/// # How it works
/// Since [`Encrypter`](Encrypter) wants to encrypt at most [`BLOCK_DATA_SIZE`](BLOCK_DATA_SIZE) bytes, internally
/// this writer will write the unencrypted data into an inner buffer. Once this buffer is filled
/// with [`BLOCK_DATA_SIZE`](BLOCK_DATA_SIZE) bytes, it's encrypted and passed into the inner writer.
///
/// If we've passed less than [`BLOCK_DATA_SIZE`](BLOCK_DATA_SIZE) bytes into this writer, and it's
/// being dropped, the leftover data inside the internal buffer is encrypted and passed into the inner writer.
/// Note that if this process fails, a panic could occur while dropping.
///
/// # Notes
/// All I/O errors which may occur in the inner reader are passed through to this one.
pub struct EncryptedWriter<W: Write> {
    encrypter: Encrypter,
    block_id: u64,
    inner: W,
    inner_buf: Vec<u8>,
}

impl<W: Write> EncryptedWriter<W> {
    /// Creates a new instance which will encrypt data using the given `password` and `salt`.
    /// The encrypted data is then passed into the `inner` writer.
    /// Internally a [`Cipher`](Cipher) and [`Encrypter`](Encrypter) are automatically created.
    ///
    /// # Panics
    /// If an instance of [`Cipher`](Cipher) or [`Encrypter`](Encrypter) could not be created, this method will panic.
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

    /// Flush the rest of the inner buffer.
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

/// # Note
/// Only `write()` and `flush()` are actually implemented.
/// All other methods will use their default implementation.
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

/// This implementation ensures that any data left in the internal buffer
/// are encrypted and written into the inner writer.
impl<W: Write> Drop for EncryptedWriter<W> {
    fn drop(&mut self) {
        self.finish().unwrap();
    }
}