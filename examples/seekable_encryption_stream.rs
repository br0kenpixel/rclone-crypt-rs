use rclone_crypt::stream::SeekableEncryptedWriter;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};

fn main() {
    let password = "test";
    let salt = "test";
    let data = "abc123";

    let mut writer = SeekableEncryptedWriter::new(
        File::create("example_file.bin").unwrap(),
        password,
        Some(salt),
    )
    .unwrap();

    writer.write_all(data.as_bytes()).unwrap();
    writer.seek(SeekFrom::Current(-1)).unwrap();
    writer.write_all(b"hello").unwrap();

    // should be `abc12hello`

    println!("Done!");
}
