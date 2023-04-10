use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use typenum::U12;

use core::mem::size_of;
use std::fs::File;
use std::{io::Read, path::Path};

pub struct Payload {
    data: Vec<u8>,
    nonce: Nonce,
    cipher: ChaCha20Poly1305,
}

impl Payload {
    pub fn new(data: Vec<u8>, key_path: &Path, nonce: Option<Nonce>) -> Self {
        fn readkey(key_path: &Path) -> Result<ChaCha20Poly1305, std::io::Error> {
            let mut buf = [0u8; 32];
            File::open(key_path)?.read(&mut buf)?;
            Ok(ChaCha20Poly1305::new_from_slice(&buf)
                .map_err(|_| std::io::ErrorKind::InvalidData)?)
        }
        Payload {
            data,
            nonce: nonce
                .or(Some(ChaCha20Poly1305::generate_nonce(&mut OsRng)))
                .unwrap(),
            cipher: readkey(key_path).unwrap_or(ChaCha20Poly1305::new(
                &ChaCha20Poly1305::generate_key(&mut OsRng),
            )),
        }
    }
    pub fn encrypt(&mut self) -> Result<(), aes_gcm::Error> {
        self.data = self.cipher.encrypt(&self.nonce, self.data.as_ref())?;
        self.data.extend_from_slice(self.nonce.as_slice());
        Ok(())
    }
    pub fn decrypt(&mut self) -> Result<(), aes_gcm::Error> {
        // TODO: Bugs here, if nonce contains zero in suffix
        self.data
            .truncate(self.data.len() - self.data.iter().rev().position(|&x| x != 0).unwrap());
        let (data, nonce) = self.data.split_at(self.data.len() - size_of::<Nonce>());
        self.nonce.copy_from_slice(&nonce);
        self.data = self.cipher.decrypt(&self.nonce, data.as_ref())?;
        Ok(())
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.data.as_slice()
    }
}

impl std::fmt::Debug for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Payload")
            .field(&self.data)
            .field(&self.nonce)
            .finish()
    }
}

impl std::fmt::Display for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "data: ")?;
        for byte in &self.data {
            write!(f, "{} ", byte)?;
        }
        write!(f, "\nnonce: {:?}\n", self.nonce.as_slice())?;
        Ok(())
    }
}
