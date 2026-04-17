use crate::node::Node;
use std::collections::{HashMap,HashSet};
#[derive(Debug,PartialEq, Eq)]
struct LKH<'a> {
    depth: HashMap<u64,HashSet<u64>>, //Association between depth (0 being root) and the set of leaves at that depth
    users: HashMap<String,&'a Node>, //Association between userID and node
    nodes: HashMap<u64,&'a Node>, //Association between nodeID and node
    root:Option<Node>,



}