use super::macros::into_io_error;
use crate::BLOCK_SIZE;
use crate::{cipher::Cipher, decrypter::Decrypter};
use crate::{FILE_HEADER_SIZE, FILE_MAGIC};
use std::io::{Error, ErrorKind, Read, Result, Seek, SeekFrom};

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
    decrypter: Decrypter,
    current_block_id: u64,
    block_content: Vec<u8>,
    seek_pos: u64,
    real_seek_pos: u64,
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
    pub fn new(inner: R, password: String, salt: Option<String>) -> Result<Self> {
        let cipher = into_io_error!(Cipher::new(password, salt), "Failed to create Cipher")?;
        Self::new_with_cipher(inner, cipher)
    }

    /// Same as [`new()`](Self::new), but takes a cipher instead of a password and a salt.
    pub fn new_with_cipher(mut inner: R, cipher: Cipher) -> Result<Self> {
        let mut header_buf = [0u8; FILE_HEADER_SIZE];
        inner
            .read_exact(&mut header_buf)
            .map_err(|_| Error::new(ErrorKind::Other, "Unable to read header"))?;

        if &header_buf[0..FILE_MAGIC.len()] != FILE_MAGIC {
            return Err(Error::new(ErrorKind::Other, "Bad Rclone header"));
        }

        let decrypter = into_io_error!(
            Decrypter::new(&cipher.get_file_key(), &header_buf),
            "Failed to create decrypter"
        )?;

        let mut first_block = vec![0u8; BLOCK_SIZE];
        let read = inner.read(&mut first_block)?;
        first_block.truncate(read);

        let decrypted = into_io_error!(
            decrypter.decrypt_block(0, &first_block),
            "Failed to decrypt first block"
        )?;

        Ok(Self {
            inner,
            decrypter,
            current_block_id: 0,
            block_content: decrypted,
            seek_pos: 0,
            real_seek_pos: 0,
        })
    }

    fn next_chunk(&mut self) -> Result<()> {
        let mut block = vec![0; BLOCK_SIZE];
        let read = self.inner.read(&mut block)?;
        block.truncate(read);

        if read == 0 {
            return Err(Error::new(ErrorKind::Other, "No more data to read"));
        }
        self.current_block_id += 1;

        let decrypted = into_io_error!(
            self.decrypter.decrypt_block(self.current_block_id, &block),
            "Failed to decrypt block"
        )?;

        self.block_content = decrypted;
        Ok(())
    }
}

impl<R: Read + Seek> EncryptedReader<R> {
    fn reset(&mut self) -> Result<()> {
        self.inner.seek(SeekFrom::Start(FILE_HEADER_SIZE as u64))?;
        self.current_block_id = 0;
        self.seek_pos = 0;
        self.real_seek_pos = 0;

        let mut first_block = vec![0u8; BLOCK_SIZE];
        let read = self.inner.read(&mut first_block)?;
        first_block.truncate(read);

        let decrypted = into_io_error!(
            self.decrypter.decrypt_block(0, &first_block),
            "Failed to decrypt first block while resetting"
        )?;
        self.block_content = decrypted;
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
            let Some(ptr) = buf.get_mut(index) else {
                break;
            };
            let Some(value) = self.block_content.get(self.seek_pos as usize) else {
                if self.next_chunk().is_err() {
                    break;
                }
                self.seek_pos = 0;
                continue;
            };

            *ptr = *value;
            index += 1;
            self.seek_pos += 1;
            self.real_seek_pos += 1;
        }
        Ok(index)
    }
}

/// # Note
/// Using `SeekFrom::Current(n)` with `n` < 0 is **NOT** supported.
impl<R: Read + Seek> Seek for EncryptedReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        match pos {
            SeekFrom::Start(n) => {
                self.reset()?;

                let mut tmpbuf = vec![0; n as usize];
                self.read_exact(&mut tmpbuf)
                    .map_err(|_| Error::new(ErrorKind::UnexpectedEof, "Invalid seek position"))?;
                Ok(n)
            }
            SeekFrom::End(n) => {
                if n < 0 {
                    return Err(Error::new(ErrorKind::Unsupported, "Negative seek position"));
                }
                let n = n as usize;

                self.reset()?;
                let mut tmpbuf = Vec::new();
                self.read_to_end(&mut tmpbuf).unwrap();
                let file_size = tmpbuf.len();

                self.reset()?;
                let seek_pos = file_size - n;
                self.seek(SeekFrom::Start(seek_pos as u64))
            }
            SeekFrom::Current(n) => {
                if n < 0 {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "Backwards seeking with SeekFrom::Current() is not supported",
                    ));
                }
                let current_seek = self.real_seek_pos;
                let mut tmpbuf = vec![0; n as usize];
                self.read_exact(&mut tmpbuf)
                    .map_err(|_| Error::new(ErrorKind::UnexpectedEof, "Invalid seek position"))?;
                Ok(current_seek + n as u64)
            }
        }
    }
}
