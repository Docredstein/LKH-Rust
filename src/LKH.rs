use crate::node::{self, Node};
use crate::tree::{BinaryTree, Tree};
use openssl::aes::AesKey;
use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, Mode, decrypt_aead, encrypt_aead};
use std::collections::{HashMap, HashSet};
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
enum Algorithm {
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

struct KeyUpdatePacket {
    new_key: Vec<u8>,
    new_key_id: u64,
    is_session_key : bool,
    delete_new_key: bool
}

impl KeyUpdatePacket {
    fn to_bytes(&self) -> Vec<u8>{
        let flags: u8= (self.is_session_key as u8) | ((self.delete_new_key as u8) <<1);
        let mut out = vec![flags];
        out.extend_from_slice(&mut self.new_key_id.to_be_bytes().to_vec());
        out.extend_from_slice(&mut self.new_key.clone());
        out
    }

    fn from_bytes(packet: Vec<u8>) -> Option<Self> {
        if packet.len()<10 {
            None
        }
       
        else {
            let flags = packet[0];
            let is_session_key = (flags & 1)==1;
            let delete_new_key = (flags & 2)==2;
            
            let key_id:[u8;8] = packet[1..9].try_into().ok()?;
            
            let id = u64::from_be_bytes(key_id);
            let key = packet[9..].to_vec();


            Some(KeyUpdatePacket {
                is_session_key:is_session_key,
                new_key:key,
                delete_new_key:delete_new_key,
                new_key_id:id
            })


        }
    }
}


impl Algorithm {
    fn key_size(&self) -> usize {
        match self {
            Algorithm::AesGcm256 => 32,
        }
    }
    fn encrypt(&self, key: &[u8], plaintext: &[u8], aad: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        match self {
            Algorithm::AesGcm256 => {
                let cipher = AesKey::new_encrypt(key).unwrap();

                let mut iv = [0 as u8; 32];
                rand_bytes(&mut iv);
                let mut tag = vec![0 as u8; 16];
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
    //users: HashMap<String, usize>, //Delegated to Tree
    algorithm: Algorithm,
    send_group: Box<dyn Fn(&[u8])>,
    debug: bool,
}

impl std::fmt::Debug for Lkh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(
            f,
            "LKH Tree of {} users using [{}]",
            self.tree.get_user_count(),
            self.algorithm
        );
    }
}

impl Lkh {
    fn generate_key_id(&self) -> u64 {
        // Generate a unique key ID (for simplicity, using a random number here)
        let mut key_id_bytes = [0u8; 8];
        rand_bytes(&mut key_id_bytes).expect("Failed to generate random key ID");
        u64::from_be_bytes(key_id_bytes)
    }
    fn generate_key(&self) -> Vec<u8> {
        let mut key = vec![0u8; self.algorithm.key_size()];
        rand_bytes(&mut key).expect("Failed to generate random key");
        key
    }

    fn update_keys(&mut self, node_id: usize, already_updated: &mut HashSet<usize>) {
        // Update keys along the path from the new node to the root
        let mut current_id = node_id;
        let is_carrying_user = self
            .tree
            .get_node_by_id(node_id)
            .as_ref()
            .map_or(false, |node| node.user.is_some());
        let mut path: Vec<(u64, Vec<u8>)> = Vec::new();

        loop {

            if already_updated.contains(&current_id) {
                let (keyid, key, parent_id) = {
                    let node = self
                        .tree
                        .get_node_by_id(current_id)
                        .expect("Node not found");

                    let keyid = node.key_id.clone();
                    let key = node.key.clone();

                    let next_id = self.tree.get_parent(current_id).as_ref().map(|n| n.id);
                    (keyid, key, next_id)
                };

                match parent_id {
                    None => break,
                    Some(next_node_id) => current_id = next_node_id,
                }
                path.push((keyid, key));
                continue;
            }
            let new_key = self.generate_key();
            let current = self.tree.get_node_by_id_mut(current_id);
            match current {
                None => break,
                Some(node) => {
                    let old_key = node.key.clone();

                    path.push((node.key_id, old_key));
                    node.key = new_key;
                }
            }
            current_id = match self.tree.get_parent(current_id) {
                None => break,
                Some(node) => node.id,
            };
            
        }

        if is_carrying_user {
            self.send_key_by_unicast(node_id, path);
        }
    }



    fn send_key_to_children(&self, node_id: usize) {
        // Send the new key to all children of the updated node
        //TODO : implement



    }

    fn send_key_by_unicast(&self, node_id: usize, path: Vec<(u64, Vec<u8>)>) {
        // Send the new key to the user of the updated node by unicast
        //TODO : implement

        
    }

    pub fn add_user(&mut self, user_id: String, send: Box<dyn Fn(&[u8])>) {
        let user = crate::user::User {
            user_id: user_id.clone(),
            send,
        };
        let node = Node {
            id: 0,
            key: self.generate_key(),
            key_id: self.generate_key_id(),
            user: Some(std::rc::Rc::new(user)),
            depth: 0,
        };
        let new_id = self.tree.add_node(node);
        self.update_keys(new_id, &mut HashSet::new());
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
            algorithm: Algorithm::AesGcm256,
            send_group: Box::new(|data| println!("Sending group data: {:?}", data)),
            debug: true,
        };
        println!("{:?}", lkh);
    }
}
