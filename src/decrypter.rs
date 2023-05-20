use crate::{calculate_nonce, cipher::FileKey, FILE_MAGIC};
use anyhow::{anyhow, Result};
use crypto_box::{aead::Aead, Nonce, PublicKey, SalsaBox, SecretKey};

pub struct Decrypter {
    secretbox: SalsaBox,
    initial_nonce: Nonce,
}

impl Decrypter {
    pub fn new(file_key: &FileKey, file_header: &[u8]) -> Result<Self> {
        let secret_key = SecretKey::from(*file_key);
        if &file_header[..FILE_MAGIC.len()] != FILE_MAGIC {
            return Err(anyhow!("Invalid file magic in file"));
        }
        let public_key = PublicKey::from(&secret_key);
        let nonce = Nonce::from_slice(&file_header[FILE_MAGIC.len()..]);

        Ok(Decrypter {
            secretbox: SalsaBox::new(&public_key, &secret_key),
            initial_nonce: *nonce,
        })
    }

    fn calculate_nonce(&self, block_id: u64) -> Nonce {
        calculate_nonce(self.initial_nonce, block_id)
    }

    pub fn decrypt_block(&self, block_id: u64, block: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.calculate_nonce(block_id);

        Ok(self.secretbox.decrypt(&nonce, block).unwrap())
    }
}
