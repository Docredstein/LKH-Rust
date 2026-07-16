
use crate::packet::{
    KeyUpdatePacket, KeylessWrappedKeyUpdatePacket, WrappedKeyUpdatePacket,
};
use rand::{RngExt, SeedableRng};
//use openssl::rand::rand_bytes;
use rand::rngs::{StdRng, SysRng};
use crate::algorithm::Algorithm;
use crate::Error;



/// Generate a random key vector
pub fn generate_key(key_size :usize) -> Vec<u8> {
        let mut key = vec![0u8; key_size];
        let mut rng = StdRng::try_from_rng(&mut SysRng).expect("Unable to seed rng");
        rng.fill(&mut key);
        key
    }
/// Encrypt a key update packet to be sent on the multicast
pub fn lkh_encrypt(
    packet: WrappedKeyUpdatePacket, algo: Algorithm, counter:u64
) -> Result<KeylessWrappedKeyUpdatePacket,crate::Error> {
todo!()
}
/// decrypt a key update received from the multicast
pub fn lkh_decrypt(
    packet: KeylessWrappedKeyUpdatePacket, key: Vec<u8>, algo: Algorithm,
) -> Option<KeyUpdatePacket> {
todo!();
}

#[cfg(test)]
mod testing {
    use super::*;

    //use crate::rand::{rand_bytes, rand_u64};
    #[test]
    fn test_encrypt_decrypt() {
        for algo in [Algorithm::AesGcm256] {
            let mut new_key = Vec::new();
            new_key.resize(algo.key_len(), 0);
            let new_key_id = 42 as u64;
            let mut ksk =Vec::new();
            ksk.resize(algo.key_len(), 1);
            let ksk_id = 32 as u64;
            let packet = KeyUpdatePacket {
                delete_new_key:false,
                is_session_key: false,
                 new_key:new_key,
                 new_key_id:new_key_id
            };
            let wrapped = packet.wrap(ksk.clone(), ksk_id);

            let cipher = lkh_encrypt(wrapped, algo,1).unwrap();
            
            let clear = lkh_decrypt(cipher, ksk, algo).unwrap();

            assert_eq!(clear,packet);
            
        }
    }
}
