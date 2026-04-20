use crate::node::Node;
use std::collections::{HashMap, HashSet};
use std::fmt;
trait BinaryTree {
    type Node;
    fn add_node(&mut self, node:  Node) -> u64;
    fn merge_nodes(&mut self, node_to_delete: Node);
    fn get_right_child(&self, node: &Node) -> &Option<Node>;
    fn get_left_child(&self, node: &Node) -> &Option<Node>;
    fn get_parent(&self, node: &Node) -> &Option<Node>;
    fn get_root(&self) -> Option<&Node>;
}
#[derive(Debug)]
struct Tree {
    //root: Option<Node>,
    //nodes: HashMap<u64, &'a Node>, //Association between nodeID and node
    depth: HashMap<u64, Vec<u64>>, //Association between depth (0 being root) and the set of leaves at that depth
    //users: HashMap<String, Vec<u64>>,  //Association between userID and node
    array: Vec<Option<Node>>,
}
//Gemini
impl fmt::Display for Tree {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Check if the array is empty or the root is None
        if self.array.is_empty() || self.array[0].is_none() {
            return writeln!(f, "Empty Tree");
        }

        writeln!(f, "Binary Tree:")?;
        
        // Start recursion from the root (ID 1, Index 0)
        self.format_node(f, 1, 0)
    }
}

impl Tree {
    // Helper function to handle indentation and child lookups
    fn format_node(&self, f: &mut fmt::Formatter, id: u64, indent: usize) -> fmt::Result {
        let index = (id - 1) as usize;

        // 1. Try to get the node at the current index
        match self.array.get(index).and_then(|slot| slot.as_ref()) {
            Some(node) => {
                // 2. Print the current node with indentation
                writeln!(f, "{:indent$}- [ID: {}] {}", "", id, node, indent = indent * 4)?;

                // 3. Calculate child IDs
                let left_id = 2 * id;
                let right_id = 2 * id + 1;

                // 4. Recurse to children if they exist in the array bounds
                // We only recurse if the index is within the array to avoid infinite loops
                if (left_id as usize) <= self.array.len() {
                    self.format_node(f, left_id, indent + 1)?;
                }
                if (right_id as usize) <= self.array.len() {
                    self.format_node(f, right_id, indent + 1)?;
                }
                Ok(())
            }
            // If the slot is None, we just don't print anything for this branch
            None => Ok(()),
        }
    }
}

impl BinaryTree for Tree {
    type Node = Node;

    fn add_node(&mut self, mut right_node: Node) -> u64 {
        let min_depth = self
            .depth
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, _)| k)
            .min()
            .copied(); //Get _a_ leaf with the smallest depth
        match min_depth {
            Some(target_depth) => {
                let target_node_id = self
                    .depth
                    .get_mut(&target_depth)
                    .expect("Target depth unavailable")
                    .pop()
                    .expect("Depth unexpectedly empty");

                if self.array.len() < (2 * target_node_id + 1) as usize {
                    self.array.resize((2 * target_node_id + 1) as usize, None);
                }

                let target_node = self
                    .array
                    .get_mut((target_node_id - 1) as usize)
                    .expect("unallowed access")
                    .as_mut()
                    .expect("Node in self.depth not in array");

                let mut left_node = target_node.clone();
                left_node.id = 2 * target_node_id;
                right_node.id = 2 * target_node_id+1;
                left_node.depth = target_node.depth + 1;
                right_node.depth = target_node.depth + 1;

                let new_depth = self.depth.get_mut(&(target_depth + 1));
                match new_depth {
                    None => {
                        let depth_set = vec![left_node.id, right_node.id];
                        self.depth.insert(target_depth + 1, depth_set);
                    }
                    Some(depth_set) => {
                        depth_set.push(left_node.id);
                        depth_set.push(right_node.id);
                    }
                }
                let l_id= (left_node.id-1) as usize;
                let r_id =(right_node.id-1) as usize;
                self.array[l_id] = Some(left_node);
                self.array[r_id] = Some(right_node);

                target_node_id
            }
            None => {
                //In this case, the tree is empty
                right_node.id = 1;
                right_node.depth = 0;
                self.array.push(Some(right_node));
                self.depth.insert(0, vec![1]);
                return 1;
            }
        }
    }

    fn merge_nodes(&mut self,mut node_to_delete:  Node) {

        
    }

    fn get_left_child(&self, node: &Node) -> &Option<Node> {
        if self.array.len() as u64 >= 2 * node.id {
            &self.array[(2 * node.id - 1) as usize]
        } else {
            &None
        }
    }

    fn get_right_child(&self, node: &Node) -> &Option<Node> {
        if self.array.len() as u64 >= 2 * node.id + 1 {
            &self.array[(2 * node.id) as usize]
        } else {
            &None
        }
    }

    fn get_parent(&self, node: &Node) -> &Option<Node> {
        // Implementation to get the parent of a node
        if self.array.len() as u64 >= node.id / 2 {
            &self.array[(node.id / 2 - 1) as usize]
        } else {
            &None
        }
    }
    fn get_root(&self) -> Option<&Node> {
        if self.array.len() <= 0 {
            return None;
        }
        match &self.array[0] {
            Some(node) => Some(&node),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let mut a = Tree {
            array: Vec::new(),
            depth: HashMap::new(),
        };

        println!("{:?}", a.get_root());
        let node = Node {
            depth: 0,
            id: 5,
            key: vec![0; 8],
            key_id: 0,
            user: None,
        };
        a.add_node(node);
        println!("{}", a);
        let node2 = Node {
            depth: 0,
            id: 5,
            key: vec![1; 8],
            key_id: 1,
            user: None,
        };
        a.add_node(node2);
        println!("{}", a);
    }

    #[test]
    fn test_medium_tree() {
        let mut a = Tree {
            array: Vec::new(),
            depth: HashMap::new(),
        };
        for i in 1..16 {
            let node = Node {
            depth: 0,
            id: 5,
            key: vec![1; 8],
            key_id: i,
            user: None,
        };
        a.add_node(node);
        print!("{}",a);
        }
    }
}
