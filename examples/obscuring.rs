/*
    This example demonstrates how to obfuscate/deobfuscate raw text.
*/

use rclone_crypt::obscure::{obscure, reveal};
use std::process::exit;

fn main() {
    let text = "Hello world!";
    let obscured = match obscure(text) {
        Ok(obscured_text) => obscured_text,
        Err(e) => {
            eprintln!("Failed to obscure text: {e}");
            exit(1);
        }
    };

    // -- Revealing --

    let revealed = match reveal(&obscured) {
        Ok(revealed_text) => revealed_text,
        Err(e) => {
            eprintln!("Failed to reveal text: {e}");
            exit(1);
        }
    };

    assert_eq!(text, revealed);

    println!("Original: {text}");
    println!("Obscured: {obscured}");
    println!("Revealed: {revealed}");
}
