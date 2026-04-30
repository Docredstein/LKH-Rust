# Logical key hierarchy implementation in rust
![Code Coverage](assets/coverage.svg)
[![CI](https://github.com/Docredstein/LKH-Rust/actions/workflows/ci.yml/badge.svg)](https://github.com/Docredstein/LKH-Rust/actions)

## Objective : 
This projet aim to implement a simple LKH implementation specifically for use in multicast trees. 

## Interface : 
- a function ```send_group(data:&[u8]) -> ()``` that send data to the multicast tree
- for each recipient
    - a function `send_unique(data:&[u8]) -> ()` that send data to the specific user **It is assumed that this communication is encrypted**
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

