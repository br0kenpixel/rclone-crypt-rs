#![allow(clippy::unused_io_amount)]
use sodiumoxide::crypto::secretbox;

/// Provides a [`Cipher`](cipher::Cipher) for encrypting
/// and decrypting file names and paths
pub mod cipher;
/// Provides a [`Decrypter`](decrypter::Decrypter) for decrypting data
pub mod decrypter;
mod eme;
/// Provides a [`Encrypter`](encrypter::Encrypter) for encrypting data
pub mod encrypter;
/// Obscuring secrects
pub mod obscure;
/// Provides streaming interfaces
pub mod stream;

/// Rclone file header magic
pub const FILE_MAGIC: &[u8] = b"RCLONE\x00\x00";
/// Nonce size
pub const FILE_NONCE_SIZE: usize = 24;
/// Header size
pub const FILE_HEADER_SIZE: usize = FILE_MAGIC.len() + FILE_NONCE_SIZE;

// Each block has an authenticated header
pub const BLOCK_HEADER_SIZE: usize = secretbox::MACBYTES;
pub const BLOCK_DATA_SIZE: usize = 64 * 1024;
pub const BLOCK_SIZE: usize = BLOCK_HEADER_SIZE + BLOCK_DATA_SIZE;

fn calculate_nonce(initial_nonce: secretbox::Nonce, block_id: u64) -> secretbox::Nonce {
    let mut nonce = secretbox::Nonce(initial_nonce.0);

    if block_id == 0 {
        return nonce;
    }

    let mut x = block_id;
    let mut carry: u16 = 0;

    for i in 0..8 {
        let digit = nonce.0[i];
        let x_digit = x as u8;
        x >>= 8;
        carry += digit as u16 + x_digit as u16;
        nonce.0[i] = carry as u8;
        carry >>= 8;
    }

    if carry != 0 {
        for i in carry as usize..FILE_NONCE_SIZE {
            let digit = nonce.0[i];
            let new_digit = digit + 1;
            nonce.0[i] = new_digit;
            if new_digit >= digit {
                // no carry
                break;
            }
        }
    }

    nonce
}

#[cfg(test)]
mod tests;
