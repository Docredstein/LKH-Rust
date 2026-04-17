use std::rc::Rc;

use crate::user::User;
#[derive(Debug,PartialEq, Eq)]
pub struct Node {
    pub id:u64,
    pub key: Vec<u8>,
    pub key_id:u64,
    pub user: Option<Rc<User>>,
    pub depth:u32
}


impl std::clone::Clone for Node {
    fn clone(&self) -> Self {
        Node {
            id: self.id,
            key: self.key.clone(),
            key_id: self.key_id,
            user: self.user.clone(),
            depth: self.depth,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

}