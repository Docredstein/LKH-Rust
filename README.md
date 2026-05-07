# Logical key hierarchy implementation in rust
![Code Coverage](assets/coverage.svg)
[![CI](https://github.com/Docredstein/LKH-Rust/actions/workflows/ci.yml/badge.svg)](https://github.com/Docredstein/LKH-Rust/actions)

## Objective : 
This projet aim to implement a simple LKH implementation specifically for use in multicast trees. 

## Interface : 
- a function ```send_group(wrapped: WrappedKeyUpdatePacket) -> ()``` that send the packet encrypted using the ksk to the multicast tree
- for each recipient
    - a function `send_unique(packet : KeyUpdatePacket) -> ()` that send data to the specific user **It is assumed that this communication is encrypted** (for example using TLS over unicast)
    - a hashable id unique to the user

## Packet used : 
(Big endian is used for the conversion from u64 to [u8])
### Key Update Packet 

```
+--------+------------+-----------+
|  Flags |   Key id   | Key value |
| 1 byte |   8 bytes  |  ? bytes  |
+--------+------------+-----------+
```

### Packet wrapped : 
(Here for AES-256-GCM)
If possible, `KSK id` should be authentified by using AAD.
```
+-----------+-----------+----------+------------+
|   KSK id  |     IV    |   Tag    | Ciphertext |
|   8 bytes |  32 bytes | 16 bytes |   ? bytes  |
+-----------+-----------+----------+------------+
```

### Tree constraint : 
Each node in the tree must follow these constraint : 
- a node is a leaf <=> the node has a user
- a node isn't a leaf <=> the node has 2 children 
- The key id follow the node during topological change
- the id denote the place of the node in the tree
- the id is defined recursively as : $$id_{Root}=1$$  $$id_{Left  Child} = 2* id_{Parent}$$ $$id_{Right  Child} = 2* id_{Parent} +1 $$
