pub struct User {
    pub user_id: String,
    pub send: Box<dyn Fn(Vec<u8>)>,
}

impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(f, "User [{}]", self.user_id);
    }
}

impl std::cmp::PartialEq for User {
    fn eq(&self, other: &Self) -> bool {
        self.user_id == other.user_id
    }
}
impl std::cmp::Eq for User {}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_print() {
        let user = User {
            user_id: "123".to_string(),
            send: Box::new(|data| println!("Sending data: {:?}", data)),
        };
        assert_eq!(format!("{:?}", user), "User [123]");
    }
    #[test]
    fn test_send() {
        let user = User {
            user_id: "123".to_string(),
            send: Box::new(|data| println!("{:?}", data)),
        };
        (user.send)(b"Hello, World!".to_vec());
    }

    #[test]
    fn test_eq_user() {
        let user1 = User {
            user_id: "1".to_string(),
            send: Box::new(|data| println!("{:?}", data)),
        };
        let user2 = User {
            user_id: "2".to_string(),
            send: Box::new(|data| println!("{:?}", data)),
        };
        let user3 = User {
            user_id: "1".to_string(),
            send: Box::new(|data| println!("{:?}", data)),
        };
        assert_ne!(user1,user2);
        assert_eq!(user1,user3);
    }
}
