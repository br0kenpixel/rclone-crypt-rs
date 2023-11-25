use crate::{cipher::Cipher, decrypter::Decrypter, BLOCK_SIZE, FILE_HEADER_SIZE, FILE_MAGIC};
use std::io::{Error, Read, Result};

/// A reader which automatically decrypts encrypted data from an inner reader.
///
/// Seeking is not supported yet.
///
/// # How it works
/// Since [`Decrypter`](Decrypter) wants to decrypt at most [`BLOCK_SIZE`](BLOCK_SIZE), internally this reader
/// will read and decrypt an entire block and store the decrypted data inside an internal buffer. When `read()`
/// is called, data is returned (and popped) from this buffer instead. If the buffer becomes empty, the next
/// block is read. If no more blocks can be read (for example in case the inner reader is exhausted), `read()`
/// will return `Ok(0)`. Calling `read()` again will just return `Ok(0)` again.  
/// I'd advise not calling it after it already returned `Ok(0)`, especially in performance-oriented
/// applications, as it will always try to read another block.
///
/// # Notes
/// All I/O errors which may occur in the inner reader are passed through to this one.
pub struct EncryptedReader<R: Read> {
    inner: R,
    crypto: Decrypter,
    block: Vec<u8>,
    block_id: u64,
}

impl<R: Read> EncryptedReader<R> {
    /// Creates a new instance which will decrypt data (read from `inner`) using the given `password` and `salt`.
    /// Internally a [`Cipher`](Cipher) and [`Decrypter`](Decrypter) are automatically created.
    ///
    /// # Notes
    /// The `inner` reader must also read the file header, otherwise it's not possible to create a [`Decrypter`](Decrypter).
    /// This header is [`FILE_HEADER_SIZE`](FILE_HEADER_SIZE) bytes long.  
    /// Example: `RCLONE\x00\x00[24 bytes of nonce]`
    ///
    /// # Errors
    /// The returned [`Result`](Result) could only contain an [`Error`](Error) if:
    /// 1. The file header read from `inner` is invalid, or
    /// 2. An I/O error occurred while trying to read the file header from `inner`, or
    /// 3. An instance of [`Cipher`](Cipher) or [`Decrypter`](Decrypter) could not be created.
    pub fn new(inner: R, password: &str, salt: Option<&str>) -> Result<Self> {
        Self::new_with_cipher(
            inner,
            Cipher::new(password, salt).map_err(|_| Error::other("Failed to create Cipher"))?,
        )
    }

    /// Same as [`new()`](Self::new), but takes a cipher instead of a password and a salt.
    #[allow(clippy::needless_pass_by_value)]
    pub fn new_with_cipher(mut inner: R, cipher: Cipher) -> Result<Self> {
        let mut header_buf = [0u8; FILE_HEADER_SIZE];
        let mut first_block = [0; BLOCK_SIZE];

        inner
            .read_exact(&mut header_buf)
            .map_err(|_| Error::other("Failed to read header"))?;

        if &header_buf[0..FILE_MAGIC.len()] != FILE_MAGIC {
            return Err(Error::other("Bad Rclone header"));
        }

        let decrypter = Decrypter::new(&cipher.get_file_key(), &header_buf)
            .map_err(|_| Error::other("Failed to create decrypter"))?;

        let read = inner.read(&mut first_block)?;
        let decrypted = decrypter
            .decrypt_block(0, &first_block[..read])
            .map_err(|_| Error::other("Failed to decrypt first block"))?;

        Ok(Self {
            inner,
            crypto: decrypter,
            block: decrypted,
            block_id: 0,
        })
    }

    /// Get and decrypt the next available block.
    /// If both operations succeed, `Ok(true)` is retuned.
    /// If we reached the end of the stream, `Ok(false)` is returned.
    /// If any of these two operations fail, an `Err(...)` variant is returned.
    fn next_block(&mut self) -> Result<bool> {
        let mut block_buf = [0; BLOCK_SIZE];
        let block_id = self.block_id + 1;
        let read = self.inner.read(&mut block_buf)?;

        if read == 0 {
            return Ok(false);
        }

        let decrypted = self
            .crypto
            .decrypt_block(block_id, &block_buf[..read])
            .map_err(|_| Error::other("Failed to decrypt block"))?;

        self.block = decrypted;
        Ok(true)
    }
}

/// # Note
/// Only `read()` is actually implemented.
/// All other methods will use their default implementation.
impl<R: Read> Read for EncryptedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.block.is_empty() {
            match self.next_block() {
                Ok(false) => return Ok(0),
                Err(why) => return Err(why),
                _ => (),
            }
        }

        let mut block = &self.block[..];
        let read = block.read(buf)?;
        self.block.drain(..read);

        Ok(read)
    }
}
