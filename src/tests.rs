use crate::{
    cipher::Cipher,
    obscure::{obscure, reveal},
};
use std::path::Path;

#[test]
fn test_path_encryption() {
    let password = String::from("test");
    let salt = String::from("test");

    let cipher = Cipher::new(password, Some(salt)).unwrap();

    let path = Path::new("test.txt");
    let encrypted = cipher.encrypt_path(path).unwrap().display().to_string();

    /*
        Rclone v1.62.2 encrypts a file named "test.txt" into the following sequence of characters
        if a crypto remote is created using the password "test" and salt "test".
    */

    assert_eq!(encrypted, "g83ktjf47lcm0bprvp034uulhg");
}

#[test]
fn password_obscure() {
    let string = String::from("hello_world");

    assert_ne!(obscure(&string).unwrap(), obscure(&string).unwrap());
}

#[test]
fn password_reveal() {
    let string = String::from("hello_world");
    let obscured = obscure(&string).unwrap();
    let revealed = reveal(&obscured).unwrap();

    assert_eq!(string, revealed);
}

#[test]
fn password_reveal_rclone() {
    let string = String::from("hello_world");
    let obscured = [
        "je8bffZYIlfYtaJszmAb96fua5e11rwU4esR",
        "up00wKh4M9ObK0B28jCBv-jDuvZxtP8NvwhR",
        "BGB9FDhquBjXI9D8IJNySNgOgbpHqxo-Gxql",
    ];

    for obscured in obscured.iter() {
        let revealed = reveal(obscured).unwrap();
        assert_eq!(string, revealed);
    }
}
