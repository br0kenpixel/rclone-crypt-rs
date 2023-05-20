use crate::{calculate_nonce, cipher::FileKey, FILE_MAGIC};
use anyhow::{anyhow, Result};
use xsalsa20poly1305::{
    aead::{Aead, KeyInit},
    Nonce, XSalsa20Poly1305,
};

pub struct Decrypter {
    key: XSalsa20Poly1305,
    initial_nonce: Nonce,
}

impl Decrypter {
    pub fn new(file_key: &FileKey, file_header: &[u8]) -> Result<Self> {
        let key = XSalsa20Poly1305::new_from_slice(file_key).unwrap();
        if &file_header[..FILE_MAGIC.len()] != FILE_MAGIC {
            return Err(anyhow!("Invalid file magic in file"));
        }
        let nonce = Nonce::from_slice(&file_header[FILE_MAGIC.len()..]);

        Ok(Decrypter {
            key,
            initial_nonce: *nonce,
        })
    }

    fn calculate_nonce(&self, block_id: u64) -> Nonce {
        calculate_nonce(self.initial_nonce, block_id)
    }

    pub fn decrypt_block(&self, block_id: u64, block: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.calculate_nonce(block_id);

        Ok(self.key.decrypt(&nonce, block).unwrap())
    }
}
