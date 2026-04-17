use crate::node::Node;
use std::collections::{HashMap,HashSet};

trait BinaryTree {
    type Node;
    fn split_node(&mut self, node: &Node);  
    fn merge_nodes(&mut self, node_to_delete: &Node);
    fn get_right_child(&self, node: &Node) -> Option<&Node>;
    fn get_left_child(&self, node: &Node) -> Option<&Node>;
    fn get_parent(&self, node: &Node) -> Option<&Node>;

}

struct Tree <'a> {
    root: Option<Node>,
    nodes: HashMap<u64,&'a Node>, //Association between nodeID and node
    depth: HashMap<u64,HashSet<u64>>, //Association between depth (0 being root) and the set of leaves at that depth
    users: HashMap<String,&'a Node>, //Association between userID and node
    array: Vec<Node>,
}

impl BinaryTree for Tree<'_> {
    type Node = Node;

    fn split_node(&mut self, node: &Node) {
        // Implementation of node splitting logic
    }

    fn merge_nodes(&mut self, node_to_delete: &Node) {
        // Implementation of node merging logic
    }

    fn get_left_child(&self, node: &Node) -> Option<&Node> {
        // Implementation to get the right child of a node
        if self.array.len() as u64>= 2*node.id {
            Some(&self.array[(2*node.id-1 ) as usize])
        } else {
            None
        }
    }

    fn get_right_child(&self, node: &Node) -> Option<&Node> {
        // Implementation to get the left child of a node
        if self.array.len() as u64>= 2*node.id +1 {
            Some(&self.array[(2*node.id ) as usize])
        } else {
            None
        }
    }

    fn get_parent(&self, node: &Node) -> Option<&Node> {
        // Implementation to get the parent of a node
        if self.array.len() as u64>= node.id/2 {
            Some(&self.array[(node.id/2 -1) as usize])
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_creation() {
        let mut tree = Tree {
            root: None,
            nodes: HashMap::new(),
            depth: HashMap::new(),
            users: HashMap::new(),
            array: Vec::new(),
        };

        assert!(tree.root.is_none());
        assert!(tree.nodes.is_empty());
        assert!(tree.depth.is_empty());
        assert!(tree.users.is_empty());
        assert!(tree.array.is_empty());
        let node1 = Node {id:1,key:vec![1,2,3],key_id:1,user:None,depth:0};
        let node2 = Node {id:2,key:vec![1,2,3],key_id:1,user:None,depth:0};
        let node3 = Node {id:3,key:vec![1,2,3],key_id:1,user:None,depth:0};
        tree.array.push(node1.clone());
        tree.array.push(node2.clone());
        tree.array.push(node3.clone());
        assert_eq!(tree.get_left_child(&node1).unwrap().id, 2);
        assert_eq!(tree.get_right_child(&node1).unwrap().id, 3);
        assert_eq!(tree.get_parent(&node2).unwrap().id, 1);
        assert_eq!(tree.get_parent(&node3).unwrap().id, 1);
    }
}