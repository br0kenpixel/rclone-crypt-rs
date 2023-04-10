use crate::BLOCK_SIZE;
use crate::{cipher::Cipher, decrypter::Decrypter};
use crate::{FILE_HEADER_SIZE, FILE_MAGIC};
use std::io::{Error, ErrorKind, Read, Result};

use super::macros::into_io_error;

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
    decrypter: Decrypter,
    block_id: u64,
    inner: R,
    inner_buf: Vec<u8>,
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
    pub fn new(mut inner: R, password: String, salt: String) -> Result<Self> {
        let mut header_buf = [0u8; FILE_HEADER_SIZE];
        inner.read_exact(&mut header_buf)?;

        if &header_buf[0..FILE_MAGIC.len()] != FILE_MAGIC {
            return Err(Error::new(ErrorKind::Other, "Bad Rclone header"));
        }

        let cipher = into_io_error!(Cipher::new(password, salt), "Failed to create Cipher")?;
        let decrypter = into_io_error!(
            Decrypter::new(&cipher.get_file_key(), &header_buf),
            "Failed to create decrypter"
        )?;

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

        let decrypted = into_io_error!(
            self.decrypter.decrypt_block(self.block_id, &buffer),
            "Failed to decrypt block"
        )?;

        self.inner_buf = decrypted;

        if read == BLOCK_SIZE {
            self.block_id += 1;
        }
        Ok(())
    }
}

/// # Note
/// Only `read()` is actually implemented.
/// All other methods will use their default implementation.
impl<R: Read> Read for EncryptedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut index = 0;

        loop {
            if self.inner_buf.is_empty() && self.next_chunk().is_err() {
                break;
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
