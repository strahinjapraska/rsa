pub(crate) const SALT_LEN: usize = 32;
pub(crate) const H_LEN: usize = 32;
pub(crate) const EM_LEN: usize = 384; 
pub(crate) const K: usize = 384;

use sha2::{Digest, Sha256};

pub (crate) fn mgf1(seed: &[u8], mask_len: usize)-> Vec<u8>{
    debug_assert!(mask_len as u64 <= 2u64.pow(32) * (H_LEN as u64)); // for the lib use case, don't need this 

    let mut t: Vec<u8> = Vec::new(); 

    let upper_bound = ((mask_len + H_LEN -1)/H_LEN) as u32;
    for c in 0u32..upper_bound{
        t.extend(Sha256::digest(&[seed, &c.to_be_bytes()].concat())); 
    }

    let mut result = vec![0u8; mask_len];
    result.copy_from_slice(&t[..mask_len]);
    result
}