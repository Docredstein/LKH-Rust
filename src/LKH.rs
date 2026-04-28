use crate::node::Node;
use crate::tree::{BinaryTree, Tree};

use colored::Colorize;
use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, decrypt_aead, encrypt_aead};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::ops::Index;

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
    is_session_key: bool,
    delete_new_key: bool,
}

impl KeyUpdatePacket {
    fn to_bytes(&self) -> Vec<u8> {
        let flags: u8 = (self.is_session_key as u8) | ((self.delete_new_key as u8) << 1);
        let mut out = vec![flags];
        out.extend_from_slice(&mut self.new_key_id.to_be_bytes().to_vec());
        out.extend_from_slice(&mut self.new_key.clone());
        out
    }

    fn from_bytes(packet: Vec<u8>) -> Option<Self> {
        if packet.len() < 10 {
            None
        } else {
            let flags = packet[0];
            let is_session_key = (flags & 1) == 1;
            let delete_new_key = (flags & 2) == 2;

            let key_id: [u8; 8] = packet[1..9].try_into().ok()?;

            let id = u64::from_be_bytes(key_id);
            let key = packet[9..].to_vec();

            Some(KeyUpdatePacket {
                is_session_key: is_session_key,
                new_key: key,
                delete_new_key: delete_new_key,
                new_key_id: id,
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
                let mut iv = [0 as u8; 32];
                rand_bytes(&mut iv).expect("Unable to generate random Bytes");
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
                match decrypt_aead(Cipher::aes_256_gcm(), key, Some(iv), aad, ciphertext, tag) {
                    Ok(plaintext) => Some(plaintext),
                    Err(e) => None,
                }
            }
        }
    }
}
pub struct Lkh {
    tree: Tree,
    //users: HashMap<String, usize>, //Delegated to Tree
    algorithm: Algorithm,
    send_group: Box<dyn Fn(Vec<u8>)>,
}

impl std::fmt::Debug for Lkh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(
            f,
            "LKH Tree of {} users using [{}] : \n{}",
            self.tree.get_user_count(),
            self.algorithm,
            self.tree
        );
    }
}

impl Lkh {
    fn get_user_count(&self) -> usize {
        self.tree.get_user_count()
    }
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

        //We also need to update the parent key_id, assuming that there is a parent

        let parent = self.tree.get_parent(node_id);
        match parent {
            None => (),
            Some(node) => {
                let parent_id = node.id;
                self.tree.get_node_by_id_mut(parent_id).expect("msg").key_id =
                    self.generate_key_id();
            }
        }

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

                    path.push((node.key_id, new_key.clone()));
                    node.key = new_key;
                }
            }
            self.send_key_to_children(current_id);

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
        #[cfg(feature = "debug")]
        {
            println!(
                "Sending new key of node {} to its children if they exist",
                node_id
            );
        }

        let session_key_id = self
            .tree
            .get_root()
            .expect("Trying to update an empty tree")
            .key_id;

        let (new_key, key_id) = match self.tree.get_node_by_id(node_id) {
            None => return,
            Some(node) => {
                let new_key = node.key.clone();
                let key_id = node.key_id;
                (new_key, key_id)
            }
        };

        let packet = KeyUpdatePacket {
            new_key: new_key,
            new_key_id: key_id,
            is_session_key: key_id == session_key_id,
            delete_new_key: false,
        }
        .to_bytes();

        match self.tree.get_left_child(node_id) {
            None => (),
            Some(node) => {
                #[cfg(feature = "debug")]
                {
                    println!("Sending new key to left child : {}", node.id);
                }

                let ksk = &node.key;
                let mut ksk_id = (&node.key_id).to_be_bytes().to_vec();

                #[cfg(feature = "debug")]
                {
                    println!(
                        "Encrypting packet for child {} with key {:x?}",
                        node.id, ksk
                    );
                }
                let (iv, tag, cipher) = self.algorithm.encrypt(ksk, &packet, &ksk_id);
                ksk_id.extend_from_slice(&iv);
                ksk_id.extend_from_slice(&tag);
                ksk_id.extend_from_slice(&cipher);

                #[cfg(feature = "debug")]
                {
                    println!("IV: {:x?}", iv);
                    println!("Tag: {:x?}", tag);
                    println!("Ciphertext: {:x?}", cipher);
                    println!("Sending group data: {:x?}", ksk_id);
                }
                (self.send_group)(ksk_id);
            }
        };
        match self.tree.get_right_child(node_id) {
            None => (),
            Some(node) => {
                #[cfg(feature = "debug")]
                {
                    println!("Sending new key to right child : {}", node.id);
                }
                let ksk = &node.key;
                let mut ksk_id = (&node.key_id).to_be_bytes().to_vec();

                let (iv, tag, cipher) = self.algorithm.encrypt(ksk, &packet, &ksk_id);
                ksk_id.extend_from_slice(&iv);
                ksk_id.extend_from_slice(&tag);
                ksk_id.extend_from_slice(&cipher);
                (self.send_group)(ksk_id);
            }
        };
    }

    fn send_key_by_unicast(&self, node_id: usize, path: Vec<(u64, Vec<u8>)>) {
        // Send the new key to the user of the updated node by unicast

        let session_key_id = self
            .tree
            .get_root()
            .expect("Trying to update a node in a tree without root")
            .key_id;

        for i in path.iter() {
            let key_id = i.0;
            let key = i.1.clone();
            let should_delete = false;
            let is_sessions_key = key_id == session_key_id;
            let packet = KeyUpdatePacket {
                new_key: key,
                new_key_id: key_id,
                is_session_key: is_sessions_key,
                delete_new_key: should_delete,
            };
            let node = self.tree.get_node_by_id(node_id);
            #[cfg(feature = "debug")]
            {
                println!(
                    "Sending key {key_id} to {0} [{1:x?}]",
                    node.expect("Wrong node").id,
                    i.1
                )
            }
            (node
                .expect("Trying to send to a non existing node")
                .user
                .as_ref()
                .expect("Trying to update the key of a non existing user")
                .as_ref()
                .send)(packet.to_bytes());
        }
    }

    pub fn add_user(&mut self, user_id: String, send: Box<dyn Fn(Vec<u8>)>) {
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

    pub fn remove_user(&mut self, user_id: &String) {
        let node_id = match self.tree.get_user_node(user_id) {
            None => return,
            Some(id) => id,
        };
        let merged_node = self.tree.merge_nodes(*node_id);
        match merged_node {
            0 => (),
            _ => {
                self.update_keys(merged_node, &mut HashSet::new());
            }
        }
    }
}

struct TestUser {
    user_id: String,
    keys: HashMap<u64, Vec<u8>>,
    algorithm: Algorithm,
    session_key_id: Option<u64>,
    in_tree: bool,
}

impl fmt::Debug for TestUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TestUser [{}] : ", self.user_id).ok();
        for (key_id, key) in self.keys.iter() {
            write!(f, "\n\t").ok();
            if self.session_key_id.is_some() && self.session_key_id.unwrap() == *key_id {
                write!(f, "\x1b[93m(Session Key)\x1b[0m ").ok();
            }
            let hexkey: String = key.iter().map(|b| format!("{:02x}", b)).collect(); //Gemini
            write!(f, "Key {} : {}", key_id, hexkey).ok();
        }
        return Ok(());
    }
}

impl TestUser {
    fn receive_single(&mut self, data: Vec<u8>) {
        let packet = KeyUpdatePacket::from_bytes(data);
        match packet {
            None => {
                #[cfg(feature = "debug")]
                {
                    println!("User {} received an invalid packet", self.user_id);
                }
            }
            Some(packet) => {
                self.keys.insert(packet.new_key_id, packet.new_key);
                if packet.is_session_key {
                    self.session_key_id = Some(packet.new_key_id);
                }
                #[cfg(feature = "debug")]
                {
                    println!(
                        "User {} updated key {} with new key {}",
                        self.user_id, packet.new_key_id, packet.new_key_id
                    );
                }
            }
        }
    }

    fn receive_group(&mut self, data: Vec<u8>) {
        //data : ksk_id,iv,tag,cipher
        #[cfg(feature = "debug")]
        {
            println!("User {} received group data", self.user_id,);

            println!("Availables keys: {:?}", self.keys);
        }
        match &self.algorithm {
            Algorithm::AesGcm256 => {
                if data.len() < (8 + 32 + 16) {
                    #[cfg(feature = "debug")]
                    {
                        println!(
                            "User {} received an invalid packet [Too short] [{} < 56]",
                            self.user_id,
                            data.len()
                        );
                    }
                    return;
                }
                let mut ksk_id_byte: [u8; 8] = [0; 8];
                ksk_id_byte.copy_from_slice(&data[..8]);
                let ksk_id = u64::from_be_bytes(ksk_id_byte);

                if !self.keys.contains_key(&ksk_id) {
                    #[cfg(feature = "debug")]
                    {
                        println!(
                            "User {} does not have the key {} needed to decrypt the packet",
                            self.user_id, ksk_id
                        );
                    }

                    return;
                }
                let ksk = self.keys.get(&ksk_id).expect("Unexpected missing key");
                let iv: [u8; 32] = data[8..40]
                    .try_into()
                    .expect("Unexpected invalid iv length");
                let tag = &data[40..56];
                let cipher = &data[56..];
                #[cfg(feature = "debug")]
                {
                    println!("IV: {:x?}", iv);
                    println!("Tag: {:x?}", tag);
                    println!("Ciphertext: {:x?}", cipher);
                    println!(
                        "User {} is trying to decrypt the packet with key {:x?}",
                        self.user_id, ksk
                    );
                }

                let packet =
                    match self
                        .algorithm
                        .decrypt(ksk, &iv, &ksk_id.to_be_bytes(), cipher, tag)
                    {
                        Some(plaintext) => plaintext,
                        None => {
                            #[cfg(feature = "debug")]
                            {
                                println!(
                                    "User {} failed to decrypt the packet with key {}",
                                    self.user_id, ksk_id
                                );
                            }
                            return;
                        }
                    };

                let key_update = KeyUpdatePacket::from_bytes(packet);
                match key_update {
                    None => {
                        #[cfg(feature = "debug")]
                        {
                            println!("GROUP : User {} received an invalid packet", self.user_id);
                        }
                    }
                    Some(packet) => {
                        self.keys.insert(packet.new_key_id, packet.new_key);
                        if packet.is_session_key {
                            self.session_key_id = Some(packet.new_key_id);
                        }
                        #[cfg(feature = "debug")]
                        {
                            println!(
                                "GROUP : User {} updated key {} with new key {}",
                                self.user_id, packet.new_key_id, packet.new_key_id
                            );
                        }
                    }
                }
            }
        }
    }
}

struct TreeTestUser {
    users: Vec<TestUser>,
}

impl fmt::Debug for TreeTestUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TreeTestUser : ").ok();
        for user in self.users.iter() {
            write!(f, "\n\t{:?}", user).ok();
        }
        return Ok(());
    }
}

impl TreeTestUser {
    fn get_user(&mut self, id: usize) -> Option<&mut TestUser> {
        self.users.get_mut(id)
    }
    fn get_user_by_id(&mut self, user_id: &String) -> Option<usize> {
        self.users.iter().position(|u| &u.user_id == user_id)
    }
    fn check_session_key(&self, session_key_id: u64) -> bool {
        self.users.iter().any(|u| {
            if u.in_tree && u.session_key_id == Some(session_key_id) {
                true
            } else if !u.in_tree && u.session_key_id != Some(session_key_id) {
                true
            } else {
                #[cfg(feature = "debug")]
                {
                    println!(
                        "User {} is in tree : {}, session key id : {:?}, expected session key id : {}",
                        u.user_id, u.in_tree, u.session_key_id, session_key_id
                    );
                }
                false
            }
        })
    }
    fn new_user(&mut self) -> usize {
        let user_id = format!("User{}", self.users.len());
        let keys = HashMap::new();
        let test_user = TestUser {
            user_id: user_id,
            keys: keys,
            algorithm: Algorithm::AesGcm256,
            session_key_id: None,
            in_tree: false,
        };
        self.users.push(test_user);
        self.users.len() - 1
    }
    fn receive_group(&mut self, data: Vec<u8>) {
        #[cfg(feature = "debug")]
        {
            println!("received group data : {:x?}", data);
        }
        for i in self.users.iter_mut() {
            i.receive_group(data.clone());
        }
    }
    fn add_user_to_tree(&mut self, id: usize) {
        self.users.get_mut(id).expect("Invalid user id").in_tree = true;
    }
    fn remove_user_from_tree(&mut self, id: usize) {
        self.users.get_mut(id).expect("Invalid user id").in_tree = false;
    }
}
#[cfg(test)]
mod tests {

    use std::{cell::RefCell, rc::Rc};

    use super::*;
    #[test]
    fn test_create() {
        let tree = Tree::new();
        let lkh = Lkh {
            tree: tree,
            algorithm: Algorithm::AesGcm256,
            send_group: Box::new(|data| println!("Sending group data: {:?}", data)),
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
        let decrypted = a
            .decrypt(&key, &iv, aad, &ciphertext, &tag)
            .expect("Unable to decrypt");
        assert_eq!(plaintext.to_vec(), decrypted);
        println!("Original : {:x?}", plaintext);
        println!("Decrypted: {:x?}", decrypted);
    }

    #[test]
    fn test_add_one_user() {
        let tree = Tree::new();
        let mut lkh = Lkh {
            tree: tree,
            algorithm: Algorithm::AesGcm256,
            send_group: Box::new(|data| println!("recieved group data: {:x?}", data)),
        };
        println!("{:?}", lkh);

        lkh.add_user(
            "User0".to_string(),
            Box::new(|data| println!("Recieved privately : {:x?}", data)),
        );
        println!("{:?}", lkh);
    }
    #[test]
    fn test_add_three_user() {
        let tree = Tree::new();
        let mut lkh = Lkh {
            tree: tree,
            algorithm: Algorithm::AesGcm256,
            send_group: Box::new(|data| println!("Sending group data: {:?}", data)),
        };
        println!("{:?}", lkh);

        lkh.add_user(
            "User0".to_string(),
            Box::new(|data| println!("0 Recieved privately : {:?}", data)),
        );
        println!("{:?}", lkh);
        lkh.add_user(
            "User1".to_string(),
            Box::new(|data| println!("1 Recieved privately : {:?}", data)),
        );
        println!("{:?}", lkh);
        lkh.add_user(
            "User2".to_string(),
            Box::new(|data| println!("2 Recieved privately : {:?}", data)),
        );
        println!("{:?}", lkh);
    }
    #[test]
    fn test_adding_one_user_realist() {
        let tree = Tree::new();
        let users = Rc::new(RefCell::new(TreeTestUser { users: Vec::new() })); //Full gemini
        let users_lkh = users.clone();
        let mut lkh = Lkh {
            tree: tree,
            algorithm: Algorithm::AesGcm256,
            send_group: Box::new(move |data| users_lkh.borrow_mut().receive_group(data)),
        };

        let user_id = users.borrow_mut().new_user();
        let unicast_user = users.clone();
        let unicast_user_id = unicast_user
            .borrow_mut()
            .get_user(user_id)
            .expect("invalid id")
            .user_id
            .clone();
        users.borrow_mut().add_user_to_tree(user_id);
        lkh.add_user(
            unicast_user_id,
            Box::new(move |data| {
                unicast_user
                    .borrow_mut()
                    .get_user(user_id)
                    .expect("invalid id")
                    .receive_single(data)
            }),
        );

        println!("{:?}", lkh);
        println!("{:?}", users);
    }
    #[test]
    fn test_adding_three_user_realist() {
        let tree = Tree::new();
        let users = Rc::new(RefCell::new(TreeTestUser { users: Vec::new() })); //Full gemini
        let users_lkh = users.clone();
        let mut lkh = Lkh {
            tree: tree,
            algorithm: Algorithm::AesGcm256,
            send_group: Box::new(move |data| users_lkh.borrow_mut().receive_group(data)),
        };
        for _ in 0..3 {
            let user_id = users.borrow_mut().new_user();
            let unicast_user = users.clone();
            let unicast_user_id = unicast_user
                .borrow_mut()
                .get_user(user_id)
                .expect("invalid id")
                .user_id
                .clone();
            users.borrow_mut().add_user_to_tree(user_id);
            lkh.add_user(
                unicast_user_id,
                Box::new(move |data| {
                    unicast_user
                        .borrow_mut()
                        .get_user(user_id)
                        .expect("invalid id")
                        .receive_single(data)
                }),
            );
            let rootkeyid = lkh.tree.get_root().expect("No root").key_id;
            assert!(users.borrow().check_session_key(rootkeyid));
            println!("{:?}", lkh);
        }
        println!("{:?}", users);
        let rootkeyid = lkh.tree.get_root().expect("No root").key_id;
        assert!(users.borrow().check_session_key(rootkeyid));
    }

    #[test]
    fn test_adding_32_user_realist() {
        let tree = Tree::new();
        let users = Rc::new(RefCell::new(TreeTestUser { users: Vec::new() })); //Full gemini
        let users_lkh = users.clone();
        let mut lkh = Lkh {
            tree: tree,
            algorithm: Algorithm::AesGcm256,
            send_group: Box::new(move |data| users_lkh.borrow_mut().receive_group(data)),
        };
        for _ in 0..32 {
            let user_id = users.borrow_mut().new_user();
            let unicast_user = users.clone();
            let unicast_user_id = unicast_user
                .borrow_mut()
                .get_user(user_id)
                .expect("invalid id")
                .user_id
                .clone();
            users.borrow_mut().add_user_to_tree(user_id);
            lkh.add_user(
                unicast_user_id,
                Box::new(move |data| {
                    unicast_user
                        .borrow_mut()
                        .get_user(user_id)
                        .expect("invalid id")
                        .receive_single(data)
                }),
            );
            let rootkeyid = lkh.tree.get_root().expect("No root").key_id;
            assert!(users.borrow().check_session_key(rootkeyid));
            println!("{:?}", lkh);
        }
        println!("{:?}", users);
        let rootkeyid = lkh.tree.get_root().expect("No root").key_id;
        assert!(users.borrow().check_session_key(rootkeyid));
    }

    #[test]
    fn test_remove_user() {
        let tree = Tree::new();
        let users = Rc::new(RefCell::new(TreeTestUser { users: Vec::new() })); //Full gemini
        let users_lkh = users.clone();
        let mut lkh = Lkh {
            tree: tree,
            algorithm: Algorithm::AesGcm256,
            send_group: Box::new(move |data| users_lkh.borrow_mut().receive_group(data)),
        };
        for _ in 0..3 {
            let user_id = users.borrow_mut().new_user();
            let unicast_user = users.clone();
            let unicast_user_id = unicast_user
                .borrow_mut()
                .get_user(user_id)
                .expect("invalid id")
                .user_id
                .clone();
            users.borrow_mut().add_user_to_tree(user_id);
            lkh.add_user(
                unicast_user_id,
                Box::new(move |data| {
                    unicast_user
                        .borrow_mut()
                        .get_user(user_id)
                        .expect("invalid id")
                        .receive_single(data)
                }),
            );
        }
        println!("{:?}", lkh);
        println!("{:?}", users);
        lkh.remove_user(&"User1".to_string());
        let user_id = users
            .borrow_mut()
            .get_user_by_id(&"User1".to_string())
            .unwrap();
        users.borrow_mut().remove_user_from_tree(user_id);
        println!("After removing User1");
        println!("{:?}", lkh);
        println!("{:?}", users);
        let rootkeyid = lkh.tree.get_root().expect("No root").key_id;
        assert!(users.borrow().check_session_key(rootkeyid));
    }

    #[test]
    fn test_remove_all_user() {
        let tree = Tree::new();
        let users = Rc::new(RefCell::new(TreeTestUser { users: Vec::new() })); //Full gemini
        let users_lkh = users.clone();
        let mut lkh = Lkh {
            tree: tree,
            algorithm: Algorithm::AesGcm256,
            send_group: Box::new(move |data| users_lkh.borrow_mut().receive_group(data)),
        };
        for _ in 0..3 {
            let user_id = users.borrow_mut().new_user();
            let unicast_user = users.clone();
            let unicast_user_id = unicast_user
                .borrow_mut()
                .get_user(user_id)
                .expect("invalid id")
                .user_id
                .clone();
            users.borrow_mut().add_user_to_tree(user_id);
            lkh.add_user(
                unicast_user_id,
                Box::new(move |data| {
                    unicast_user
                        .borrow_mut()
                        .get_user(user_id)
                        .expect("invalid id")
                        .receive_single(data)
                }),
            );
            let rootkeyid = lkh.tree.get_root().expect("No root").key_id;
            assert!(users.borrow().check_session_key(rootkeyid));
        }
        println!("{:?}", lkh);
        println!("{:?}", users);
        for i in 0..3 {
            lkh.remove_user(&format!("User{}", i));
            let user_id = users
                .borrow_mut()
                .get_user_by_id(&format!("User{}", i))
                .unwrap();
            users.borrow_mut().remove_user_from_tree(user_id);
            if lkh.get_user_count() > 0 {
                println!("Users count : {}", lkh.get_user_count());
                let rootkeyid = lkh.tree.get_root().expect("No root").key_id;
                assert!(users.borrow().check_session_key(rootkeyid));
            }
        }
        println!("After removing all users");
        println!("{:?}", lkh);
        println!("{:?}", users);
    }
    #[test]
    fn random_test() {
        let tree = Tree::new();
        let users = Rc::new(RefCell::new(TreeTestUser { users: Vec::new() })); //Full gemini
        let users_lkh = users.clone();
        let n = 32;
        let mut lkh = Lkh {
            tree: tree,
            algorithm: Algorithm::AesGcm256,
            send_group: Box::new(move |data| users_lkh.borrow_mut().receive_group(data)),
        };
        for _ in 0..n {
            users.borrow_mut().new_user();
        }
        let mut actions = Vec::new();
        for _ in 0..100000 {
            println!("Actions : {:?}", actions);
            let user_id = (rand::random::<u64>() % n) as usize;
            let user_in_vec = users
                .borrow_mut()
                .get_user_by_id(&format!("User{}", user_id).to_string())
                .expect("User unexpectedly not in array");
            let in_tree = users
                .borrow_mut()
                .get_user(user_in_vec)
                .expect("Unexpectedly not in array")
                .in_tree
                .clone();
            println!("{:?}", lkh.tree.depth);
            println!("{}", lkh.tree);
            if !in_tree {
                //Add user
                println!("Adding User{}", user_id);
                actions.push(format!("Adding User{}", user_id));
                let unicast_user = users.clone();
                let unicast_user_id = unicast_user
                    .borrow_mut()
                    .get_user(user_id)
                    .expect("invalid id")
                    .user_id
                    .clone();
                users.borrow_mut().add_user_to_tree(user_id);
                lkh.add_user(
                    unicast_user_id,
                    Box::new(move |data| {
                        unicast_user
                            .borrow_mut()
                            .get_user(user_id)
                            .expect("invalid id")
                            .receive_single(data)
                    }),
                );
            } else {
                println!("Removing User{}", user_id);

                actions.push(format!("Removing User{}", user_id));
                //Remove user
                lkh.remove_user(&format!("User{}", user_id));
                users.borrow_mut().remove_user_from_tree(user_id);
            }
            assert!(lkh.tree.verify_integrity());
        }
    }
}
