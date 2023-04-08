/*
    This example demonstrates how to encrypt/decrypt a data block.

    You may notice that the encrypted bytes are different every time you run this
    code. That's probably because internally a random number is used for some
    cryptographic stuff and so the result is always different, but it's still the
    same data.

    `encrypted_result` - contains the actual raw bytes that Rclone would put inside
    an encrypted file.
*/

use rclone_crypt::{cipher::Cipher, decrypter::Decrypter, encrypter::Encrypter};
use std::process::exit;

fn main() {
    let password = String::from("super_secret_password");
    let salt = String::from("salty");
    let segment_content = "and that's how we learn Rust";

    let cipher = match Cipher::new(password, salt) {
        Ok(cipher) => cipher,
        Err(e) => {
            eprintln!("Failed to create a Cipher: {e}");
            exit(0);
        }
    };
    let encrypter = Encrypter::new(&cipher.file_key).unwrap();

    // -- Encryption --

    let encrypted = encrypter.encrypt_block(0, segment_content.as_bytes());
    let mut encrypted_result = encrypter.get_file_header();
    encrypted_result.extend(&encrypted);

    // -- Decryption --

    let decrypter = Decrypter::new(&cipher.file_key, &encrypter.get_file_header()).unwrap();
    let decrypted_result = decrypter.decrypt_block(0, &encrypted).unwrap();
    let decrypted_result = String::from_utf8(decrypted_result).unwrap();

    assert_eq!(decrypted_result, segment_content.to_string());

    println!("Segment: \"{}\"", segment_content);
    println!("Encrypted: {:02x?}", encrypted_result);
    println!("Decrypted: \"{}\"", decrypted_result);
}
