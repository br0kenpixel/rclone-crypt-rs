/*
    This example demonstrates how to encrypt/decrypt a file name.
*/

use rclone_crypt::cipher::Cipher;
use std::process::exit;

fn main() {
    let password = String::from("super_secret_password");
    let salt = String::from("salty");

    let cipher = match Cipher::new(password, Some(salt)) {
        Ok(cipher) => cipher,
        Err(e) => {
            eprintln!("Failed to create a Cipher: {e}");
            exit(0);
        }
    };

    // -- Encryption --

    let file_name = "Rust Tutorial.pdf";
    let encrypted = match cipher.encrypt_file_name(file_name) {
        Ok(encrypted_file_name) => encrypted_file_name,
        Err(e) => {
            eprintln!("Failed to encrypt file name: {e}");
            exit(0);
        }
    };

    // -- Decryption --

    let decrypted = match cipher.decrypt_file_name(&encrypted) {
        Ok(decrypted_file_name) => decrypted_file_name,
        Err(e) => {
            eprintln!("Failed to decrypt file name: {e}");
            exit(0);
        }
    };

    assert_eq!(decrypted, file_name);

    println!("File name: {file_name}");
    println!("Encrypted: {encrypted}");
    println!("Decrypted: {decrypted}");
}
