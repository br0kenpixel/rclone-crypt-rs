use crate::{calculate_nonce, cipher::FileKey, FILE_HEADER_SIZE, FILE_MAGIC};
use anyhow::Result;
use xsalsa20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    Nonce, XSalsa20Poly1305,
};

pub struct Encrypter {
    key: XSalsa20Poly1305,
    initial_nonce: Nonce,
}

impl Encrypter {
    pub fn new(file_key: &FileKey) -> Result<Self> {
        let key = XSalsa20Poly1305::new_from_slice(file_key).unwrap();

        Ok(Encrypter {
            key,
            initial_nonce: XSalsa20Poly1305::generate_nonce(&mut OsRng),
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

        self.key.encrypt(&nonce, block).unwrap()
    }
}
