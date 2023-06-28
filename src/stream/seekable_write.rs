use super::macros::into_io_error;
use crate::BLOCK_DATA_SIZE;
use crate::{cipher::Cipher, encrypter::Encrypter};
use std::io::{Cursor, Error, ErrorKind, Result, Seek, SeekFrom, Write};

/// A less secure and more memory intensive writer, which supports seeking.
///
/// The inner writer does __not__ need to implement [`Seek`](Seek).
///
/// # How it works
/// This writer keeps all data in an internal buffer, which means that all the raw (non-encrypted) data
/// is kept in memory. When this writer is dropped, the inner buffer is encrypted and written into the
/// inner writer.
///
///
/// # Notes
/// Since all the non-encrypted) data is kept in memory during the entire lifetime of this writer, it's
/// significantly less secure than [`EncryptedWriter`](crate::stream::EncryptedWriter), but on the other
/// hand, allows seeking. If the inner writer is slow, dropping may be slow as well.
///
/// # Panics
/// The `drop()`method uses a bunch of `unwrap()`s so, any failed write operation will cause a panic.
pub struct SeekableEncryptedWriter<W: Write> {
    encrypter: Encrypter,
    inner: W,
    inner_buf: Cursor<Vec<u8>>,
}

impl<W: Write> SeekableEncryptedWriter<W> {
    /// Creates a new instance which will encrypt data using the given `password` and `salt`.
    /// The encrypted data is then passed into the `inner` writer.
    /// Internally a [`Cipher`](Cipher) and [`Encrypter`](Encrypter) are automatically created.
    ///
    /// # Errors
    /// The returned [`Result`](Result) could only contain an [`Error`](Error) if an instance
    /// of [`Cipher`](Cipher) or [`Encrypter`](Encrypter) could not be created.
    pub fn new(inner: W, password: &str, salt: Option<&str>) -> Result<Self> {
        let cipher = into_io_error!(Cipher::new(password, salt), "Failed to create Cipher")?;
        Self::new_with_cipher(inner, cipher)
    }

    /// Same as [`new()`](Self::new) but takes a cipher instead of a password and a salt.
    pub fn new_with_cipher(inner: W, cipher: Cipher) -> Result<Self> {
        let encrypter = into_io_error!(
            Encrypter::new(&cipher.get_file_key()),
            "Failed to create Encrypter"
        )?;

        Ok(Self {
            encrypter,
            inner,
            inner_buf: Cursor::new(Vec::new()),
        })
    }
}

impl<W: Write> Write for SeekableEncryptedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.inner_buf.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.inner_buf.flush()
    }
}

impl<W: Write> Seek for SeekableEncryptedWriter<W> {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        self.inner_buf.seek(pos)
    }
}

impl<W: Write> Drop for SeekableEncryptedWriter<W> {
    fn drop(&mut self) {
        let inner_buf = self.inner_buf.get_mut();
        let blocks = inner_buf.chunks(BLOCK_DATA_SIZE);

        self.inner
            .write_all(&self.encrypter.get_file_header())
            .unwrap();

        for (block_id, block) in blocks.enumerate() {
            let encrypted = self.encrypter.encrypt_block(block_id as u64, block);
            self.inner.write_all(&encrypted).unwrap();
        }
        self.inner.flush().unwrap();
    }
}
