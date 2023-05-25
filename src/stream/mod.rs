mod read;
mod seekable_write;
mod write;

mod macros {
    /// Convert an arbitrary `Result` into an std::io::Result
    macro_rules! into_io_error {
        ($result_obj: expr, $error_text: literal) => {
            $result_obj.map_err(|_| Error::new(ErrorKind::Other, $error_text))
        };
    }

    pub(super) use into_io_error;
}

pub use read::EncryptedReader;
pub use seekable_write::SeekableEncryptedWriter;
pub use write::EncryptedWriter;
