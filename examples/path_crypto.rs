/*
    This example demonstrates how to encrypt/decrypt a file path.
*/

use rclone_crypt::cipher::Cipher;
use std::{path::Path, process::exit};

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

    let path = Path::new("/home/user/Rust Tutorial.pdf");
    let encrypted = match cipher.encrypt_path(path) {
        Ok(encrypted_path) => encrypted_path,
        Err(e) => {
            eprintln!("Failed to encrypt file path: {e}");
            exit(0);
        }
    };

    // -- Decryption --

    let decrypted = match cipher.decrypt_path(&encrypted) {
        Ok(decrypted_path) => decrypted_path,
        Err(e) => {
            eprintln!("Failed to decrypt file path: {e}");
            exit(0);
        }
    };

    assert_eq!(decrypted, path);

    println!("Path: {}", path.display());
    println!("Encrypted: {}", encrypted.display());
    println!("Decrypted: {}", decrypted.display());
}
