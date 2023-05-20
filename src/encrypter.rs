use crate::{calculate_nonce, cipher::FileKey, FILE_HEADER_SIZE, FILE_MAGIC};
use anyhow::Result;
use crypto_box::{
    aead::{Aead, AeadCore},
    rand_core::OsRng,
    Nonce, PublicKey, SalsaBox, SecretKey,
};

pub struct Encrypter {
    secretbox: SalsaBox,
    initial_nonce: Nonce,
}

impl Encrypter {
    pub fn new(file_key: &FileKey) -> Result<Self> {
        let secret_key = SecretKey::from(*file_key);
        let public_key = PublicKey::from(&secret_key);

        Ok(Encrypter {
            secretbox: SalsaBox::new(&public_key, &secret_key),
            initial_nonce: SalsaBox::generate_nonce(OsRng),
        })
    }

    fn calculate_nonce(&self, block_id: u64) -> Nonce {
        calculate_nonce(self.initial_nonce, block_id)
    }

    pub fn get_file_header(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FILE_HEADER_SIZE);
        out.extend_from_slice(FILE_MAGIC);
        out.extend_from_slice(self.initial_nonce.as_ref());

        out
    }

    pub fn encrypt_block(&self, block_id: u64, block: &[u8]) -> Vec<u8> {
        let nonce = self.calculate_nonce(block_id);

        self.secretbox.encrypt(&nonce, block).unwrap()
    }
}
