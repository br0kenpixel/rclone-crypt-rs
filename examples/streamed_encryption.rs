use rclone_crypt::stream::EncryptedWriter;
use std::fs::File;
use std::io::Write;

fn main() {
    let password = String::from("test");
    let salt = String::from("test");
    let data = String::from("abc123");

    let mut writer =
        EncryptedWriter::new(File::create("example_file.bin").unwrap(), password, salt).unwrap();

    writer.write_all(data.as_bytes()).unwrap();
    println!("Done! Encrypted {} bytes", data.len());
}
