use std::rc::Rc;
use std::fmt::{self, write};
use crate::user::User;
#[derive(Debug, PartialEq, Eq)]
pub struct Node {
    pub id: u64,
    pub key: Vec<u8>,
    pub key_id: u64,
    pub user: Option<Rc<User>>,
    pub depth: u64,
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
impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Node of key [{}] : ",self.key_id);
        match &self.user  {
            None =>     write!(f,"None"),
            Some(user) => write!(f, "{}", user.user_id)
        }

        
        
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
