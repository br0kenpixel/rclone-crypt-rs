use rclone_crypt::stream::EncryptedReader;
use std::fs::File;
use std::io::Read;

fn main() {
    let password = String::from("test");
    let salt = String::from("test");

    let mut reader = EncryptedReader::new(
        File::open("example_file.bin").unwrap(),
        password,
        Some(salt),
    )
    .unwrap();
    let mut buf = String::new();

    reader.read_to_string(&mut buf).unwrap();
    println!("{buf}");
}
