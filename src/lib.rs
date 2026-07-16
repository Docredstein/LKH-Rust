
pub mod node;
pub mod user;
pub mod tree;
pub mod lkh;
pub mod packet;
pub mod lkhcrypto;
pub mod algorithm;


#[derive(Debug,Clone, Copy)]
pub enum Error {
    RekeyingError,
    EncryptError,
    MissingNode
}