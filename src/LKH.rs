use crate::node::Node;
use std::collections::{HashMap,HashSet};








struct lkh<'a> {
    depth: HashMap<u64,HashSet<u64>>, //Association between depth (0 being root) and the set of leaves at that depth
    users: HashMap<String,&'a Node>, //Association between userID and node
    nodes: HashMap<u64,&'a Node>, //Association between nodeID and node
    root:Option<Node>,
    send_group: Box<dyn Fn(&[u8])>,
}


impl std::fmt::Debug for lkh<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(f, "LKH Tree of {} users", self.users.len());
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_create() {
        let tree  = lkh {
            depth: HashMap::new(),
            users: HashMap::new(),
            nodes: HashMap::new(),
            root: None,
            send_group: Box::new(|data| println!("Sending data to group: {:?}", data)),
        };
        println!("{:?}", tree);

    }
}