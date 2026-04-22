use crate::node::Node;
use crate::tree::{BinaryTree, Tree};
use std::fmt;
use openssl::aes::{AesKey};
use openssl::symm::{Mode,encrypt_aead,Cipher,decrypt_aead};
use openssl::rand::rand_bytes;
use std::collections::{HashMap, HashSet};


#[derive(Debug, PartialEq, Eq)]
enum Algorithm {
    AesGcm256,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", match self {
            Algorithm::AesGcm256 => "AES-GCM-256",})
    }
}

impl Algorithm {
    fn key_size(&self) -> usize {
        match self {
            Algorithm::AesGcm256 => 32,
        }
    }
    fn encrypt(&self, key: &[u8], plaintext: &[u8],aad:  &[u8]) -> (Vec<u8>,Vec<u8>,Vec<u8>) {
        match self {
            Algorithm::AesGcm256 => {
                let cipher = AesKey::new_encrypt(key).unwrap();
                
                let mut iv = [0 as u8 ; 32];
                rand_bytes(&mut iv);
                let mut tag = vec![0 as u8; 16];
                match encrypt_aead(Cipher::aes_256_gcm(), key, Some(&iv), aad, plaintext, &mut tag) {
                    Ok(ciphertext) => (iv.to_vec(),tag,ciphertext),
                    Err(e) => panic!("Encryption failed: {:?}", e),
                }
                
                
            }
        }
    }
    fn decrypt(&self, key: &[u8], iv: &[u8], aad: &[u8], ciphertext: &[u8], tag: &[u8]) -> Vec<u8> {
        match self {
            Algorithm::AesGcm256 => {
                match decrypt_aead(Cipher::aes_256_gcm(), key, Some(iv), aad, ciphertext, tag) {
                    Ok(plaintext) => plaintext,
                    Err(e) => panic!("Decryption failed: {:?}", e),
                }
            }
        }
    }
}
pub struct Lkh {
    tree: Tree,
    users: HashMap<String, usize>,
    algorithm: Algorithm,
    send_group: Box<dyn Fn(&[u8])>,
    debug: bool,
}

impl std::fmt::Debug for Lkh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(
            f,
            "LKH Tree of {} users using [{}]",
            self.users.len(),
            self.algorithm
        );
    }
}

impl Lkh {

    pub fn add_user(&mut self, user_id: String, send: Box<dyn Fn(&[u8])>) {
        let user = crate::user::User {
            user_id: user_id.clone(),
            send,
        };
        let node = Node {
            id: 0,
            key: vec![],
            key_id: 0,
            user: Some(std::rc::Rc::new(user)),
            depth: 0,
        };
        let new_id = self.tree.add_node(node);
        self.users.insert(user_id, new_id);

    }




}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_create() {
        let tree = Tree::new();
        let lkh = Lkh {
            tree: tree,
            users: HashMap::new(),
            algorithm: Algorithm::AesGcm256,
            send_group: Box::new(|data| println!("Sending group data: {:?}", data)),
            debug: true,
        };
        println!("{:?}", lkh);
    }
    #[test]
    fn test_encrypt() {
        let a = Algorithm::AesGcm256;
        let key = vec![0; a.key_size()];
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
        let key = vec![0; a.key_size()];
        let plaintext = b"Hello, World!";
        let aad = b"Additional Data";
        let (iv, tag, ciphertext) = a.encrypt(&key, plaintext, aad);
        let decrypted = a.decrypt(&key, &iv, aad, &ciphertext, &tag);
        assert_eq!(plaintext.to_vec(), decrypted);
        println!("Original : {:x?}", plaintext);
        println!("Decrypted: {:x?}", decrypted);
    }

        #[test]
    fn test_add_one_user() {
        let tree = Tree::new();
        let lkh = Lkh {
            tree: tree,
            users: HashMap::new(),
            algorithm: Algorithm::AesGcm256,
            send_group: Box::new(|data| println!("Sending group data: {:?}", data)),
            debug: true,
        };
        println!("{:?}", lkh);
    }
}
