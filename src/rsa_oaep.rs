use crate::{rsa}; 
use crate::common::*;  
use crypto_bigint::U3072;
use sha2::{Digest, Sha256};
use rand::RngCore;


pub fn keygen() -> (rsa::RSAPublicKey, rsa::RSAPrivateKey) {
    rsa::keygen()
}

pub fn enc(pk: &rsa::RSAPublicKey, m: &[u8], l: &[u8]) -> [u8; 384]{
    assert!((l.len() as u64) <= 2u64.pow(61) - 1);  

    assert!(m.len() <= K - 2*H_LEN - 2); 

    let em = eme_oaep_encode(m, l);  

    let c = rsa::enc(pk, &U3072::from_be_slice(&em)); 
    
    return c.to_be_bytes(); 
}

pub fn dec(sk: &rsa::RSAPrivateKey, c: &[u8]) -> Vec<u8>{
    unimplemented!();
}

pub fn eme_oaep_encode(m: &[u8], l: &[u8]) -> [u8; K]{
    let l_hash = Sha256::digest(l); 

    let ps = vec![0u8; K - m.len() - 2*H_LEN - 2];

    let mut db = [0u8; K - H_LEN - 1]; 
    db[..H_LEN].copy_from_slice(&l_hash);
    db[H_LEN..H_LEN+ps.len()].copy_from_slice(&ps); 
    db[H_LEN+ps.len()] = 0x01;
    db[H_LEN+ps.len()+1..].copy_from_slice(m);  

    let mut seed = [0u8; H_LEN]; 
    rand::rng().fill_bytes(&mut seed);  

    let db_mask = mgf1(&seed, K - H_LEN - 1);  
    let mut masked_db = [0u8; K - H_LEN - 1]; 

    for i in 0..db_mask.len(){
        masked_db[i] = db[i] ^ db_mask[i];
    } 

    let seed_mask = mgf1(&masked_db, H_LEN); 
    let mut masked_seed = [0u8; H_LEN]; 

    for i in 0..seed_mask.len(){
        masked_seed[i] = seed[i] ^ seed_mask[i];
    }

    let mut em = [0u8; K]; 
    em[1..1+H_LEN].copy_from_slice(&masked_seed);
    em[1+H_LEN..].copy_from_slice(&masked_db);

    return em; 
}

