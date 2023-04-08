use crate::cipher::Cipher;
use std::path::Path;

#[test]
fn test_path_encryption() {
    let password = String::from("test");
    let salt = String::from("test");

    let cipher = Cipher::new(password, salt).unwrap();

    let path = Path::new("test.txt");
    let encrypted = cipher.encrypt_path(path).unwrap().display().to_string();

    /*
        Rclone v1.62.2 encrypts a file named "test.txt" into the following sequence of characters
        if a crypto remote is created using the password "test" and salt "test".
    */

    assert_eq!(encrypted, "g83ktjf47lcm0bprvp034uulhg");
}
