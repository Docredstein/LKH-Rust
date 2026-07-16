use openssl::symm::{Cipher, decrypt_aead, encrypt_aead};
use std::fmt;
use openssl::rand::rand_bytes;
use std::collections::HashMap;
#[derive(Debug, PartialEq, Eq,Clone,Copy)]
// TODO: add a way to select the algorithm used
pub enum Algorithm {
    AesGcm256,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Algorithm::AesGcm256 => "AES-GCM-256",
            }
        )
    }
}


impl Algorithm {
    pub fn key_len(&self) -> usize {
        match self {
            Algorithm::AesGcm256 => 32,
        }
    }
    fn tag_size(&self) -> usize {
        match self {
            Algorithm::AesGcm256 => 16,
        }
    }
    fn iv_size(&self) -> usize {
        match self {
            Algorithm::AesGcm256 => 32,
        }
    }
    fn encrypt(&self, key: &[u8], plaintext: &[u8], aad: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        match self {
            Algorithm::AesGcm256 => {
                let mut iv = [0_u8; 32];
                rand_bytes(&mut iv).expect("Unable to generate random Bytes");
                let mut tag = vec![0_u8; self.tag_size()];
                match encrypt_aead(
                    Cipher::aes_256_gcm(),
                    key,
                    Some(&iv),
                    aad,
                    plaintext,
                    &mut tag,
                ) {
                    Ok(ciphertext) => (iv.to_vec(), tag, ciphertext),
                    Err(e) => panic!("Encryption failed: {:?}", e),
                }
            }
        }
    }
    fn decrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8],
    ) -> Option<Vec<u8>> {
        match self {
            Algorithm::AesGcm256 => {
                decrypt_aead(Cipher::aes_256_gcm(), key, Some(iv), aad, ciphertext, tag).ok()
            }
        }
    }
    fn wrap(&self, data: &[u8], key: &[u8], key_id: u64) -> Vec<u8> {
        let mut ksk_id = key_id.to_be_bytes().to_vec();

        let (iv, tag, cipher) = self.encrypt(key, data, &ksk_id);
        ksk_id.extend_from_slice(&iv);
        ksk_id.extend_from_slice(&tag);
        ksk_id.extend_from_slice(&cipher);
        ksk_id
    }
    fn unwrap(&self, packet: &[u8], keys: &HashMap<u64, Vec<u8>>) -> Option<Vec<u8>> {
        if packet.len() < (8 + self.iv_size() + self.tag_size()) {
            None
        } else {
            let ksk_id_byte: [u8; 8] = packet[..8].try_into().ok()?;
            let ksk_id = u64::from_be_bytes(ksk_id_byte);
            let key = keys.get(&ksk_id)?;
            let iv = &packet[8..8 + self.iv_size()];
            let tag = &packet[8 + self.iv_size()..8 + self.iv_size() + self.tag_size()];
            let cipher = &packet[8 + self.iv_size() + self.tag_size()..];
            self.decrypt(key, iv, &ksk_id_byte, cipher, tag)
        }
    }
}


#[cfg(test)]
mod tests {
use super::*;
#[test]
    fn test_encrypt() {
        let a = Algorithm::AesGcm256;
        let key = vec![0; a.key_len()];
        let plaintext = b"Hello, World!";
        let aad = b"Additional Data";
        let (iv, tag, ciphertext) = a.encrypt(&key, plaintext, aad);
        println!("IV: {:x?}", iv);
        println!("Tag: {:x?}", tag);
        println!("Ciphertext: {:x?}", ciphertext);
    }
    #[test]
    fn test_encrypt_decrypt() {
        let a = Algorithm::AesGcm256;
        let key = vec![0; a.key_len()];
        let plaintext = b"Hello, World!";
        let aad = b"Additional Data";
        let (iv, tag, ciphertext) = a.encrypt(&key, plaintext, aad);
        let decrypted = a
            .decrypt(&key, &iv, aad, &ciphertext, &tag)
            .expect("Unable to decrypt");
        assert_eq!(plaintext.to_vec(), decrypted);
        println!("Original : {:x?}", plaintext);
        println!("Decrypted: {:x?}", decrypted);
    }
}