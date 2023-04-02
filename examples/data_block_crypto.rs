/*
    This example demonstrates how to encrypt/decrypt a data block.
*/

use rclone_crypt::cipher::Cipher;
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

    // -- Encryption --

    let encrypted = match cipher.encrypt_segment(segment_content) {
        Ok(encrypted_segment) => encrypted_segment,
        Err(e) => {
            eprintln!("Failed to encrypt segment: {e}");
            exit(0);
        }
    };

    // -- Decryption --

    let decrypted = match cipher.decrypt_segment(&encrypted) {
        Ok(decrypted_segment) => decrypted_segment,
        Err(e) => {
            eprintln!("Failed to decrypt segment: {e}");
            exit(0);
        }
    };

    assert_eq!(decrypted, segment_content);

    println!("Segment: \"{}\"", segment_content);
    println!("Encrypted: {}", encrypted);
    println!("Decrypted: \"{}\"", decrypted);
}
