use crate::user::User;
#[derive(Debug,PartialEq, Eq)]
pub struct Node {
    id:u64,
    key: Vec<u8>,
    key_id:u64,
    user: Option<User>,
    depth:u32
}

#[cfg(test)]
mod tests {
    use super::*;
    
}