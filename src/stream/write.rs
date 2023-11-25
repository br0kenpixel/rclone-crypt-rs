use crate::{cipher::Cipher, encrypter::Encrypter, BLOCK_DATA_SIZE};
use std::io::{Error, Result, Write};

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
    inner: W,
    crypto: Encrypter,
    block: Vec<u8>,
    block_id: u64,
}

impl<W: Write> EncryptedWriter<W> {
    /// Creates a new instance which will encrypt data using the given `password` and `salt`.
    /// The encrypted data is then passed into the `inner` writer.
    /// Internally a [`Cipher`](Cipher) and [`Encrypter`](Encrypter) are automatically created.
    ///
    /// # Errors
    /// The returned [`Result`](Result) could only contain an [`Error`](Error) if an instance
    /// of [`Cipher`](Cipher) or [`Encrypter`](Encrypter) could not be created.
    pub fn new(inner: W, password: &str, salt: Option<&str>) -> Result<Self> {
        let cipher =
            Cipher::new(password, salt).map_err(|_| Error::other("Failed to create Cipher"))?;

        Self::new_with_cipher(inner, cipher)
    }

    /// Same as [`new()`](Self::new) but takes a cipher instead of a password and a salt.
    pub fn new_with_cipher(inner: W, cipher: Cipher) -> Result<Self> {
        let encrypter = Encrypter::new(&cipher.get_file_key())
            .map_err(|_| Error::other("Failed to create Encrypter"))?;

        Ok(Self {
            inner,
            crypto: encrypter,
            block: Vec::new(),
            block_id: 0,
        })
    }

    /// Encrypts the current block of data and writes it to the underlying writer.
    /// If this is called for the first time, the file header is automatically generated and written too.
    /// If an I/O error occurs, it's returned.
    ///
    /// # Notes
    /// - `block_id` is incremented automatically
    /// - Calling this on an empty block does nothing
    fn finish(&mut self) -> Result<()> {
        if self.block.is_empty() {
            return Ok(());
        }

        if self.block_id == 0 {
            self.inner.write_all(&self.crypto.get_file_header())?;
        }

        let encrypted = self.crypto.encrypt_block(self.block_id, &self.block);
        self.inner.write_all(&encrypted)?;
        self.block.clear();
        self.block_id += 1;

        Ok(())
    }
}

/// # Note
/// Only `write()` and `flush()` are actually implemented.
/// All other methods will use their default implementation.
impl<W: Write> Write for EncryptedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let block_length = self.block.len();
        let mut free = BLOCK_DATA_SIZE - block_length;

        if free == 0 {
            self.finish()?;
            free = BLOCK_DATA_SIZE;
        }

        let read = free.clamp(0, buf.len());
        self.block.extend_from_slice(&buf[..read]);

        Ok(read)
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
