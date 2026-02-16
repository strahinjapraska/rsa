use std::ops::BitAnd;

use crate::{rsa}; 
use crate::common::*;  
use crypto_bigint::U3072;
use crypto_bigint::subtle::{Choice, ConstantTimeEq};
use sha2::{Digest, Sha256};
use rand::RngCore;


pub fn keygen() -> (rsa::RSAPublicKey, rsa::RSAPrivateKey) {
    rsa::keygen()
}

pub fn enc(pk: &rsa::RSAPublicKey, m: &[u8], l: &[u8]) -> Result<[u8; 384], String>{
    if (l.len() as u64) > 2u64.pow(61) - 1{
        return Err("label too long".to_string()); 
    }

    if m.len() > K - 2*H_LEN - 2 {
        return Err("message too long".to_string());
    }

    let em = eme_oaep_encode(m, l);  


    match rsa::enc(pk, &U3072::from_be_slice(&em)){
        Ok(c) => return Ok(c.to_be_bytes()),  
        Err(e) => return Err(e)
    }
    
    
}

pub fn dec(sk: &rsa::RSAPrivateKey, c: &[u8], l: &[u8]) -> Result<Vec<u8>, String>{
    if (l.len() as u64) > 2u64.pow(61) - 1 || c.len() != K || K < 2*H_LEN + 2{
        return Err("Decryption failed".to_string())
    }

    match rsa::dec(sk, &U3072::from_be_slice(c)){
        Ok(em_integer) => {
            let em = em_integer.to_be_bytes();
            return eme_oaep_decode(&em, l); 
        }, 
        Err(_) => return Err("Decryption failed".to_string())
    }
   
}

pub fn eme_oaep_encode(m: &[u8], l: &[u8]) -> [u8; K]{
    let l_hash = if l.len() == 0{
        [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ]
    }else{
        Sha256::digest(l).into()
    }; 

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

pub fn eme_oaep_decode(em: &[u8], l: &[u8]) -> Result<Vec<u8>, String> {
     let l_hash = if l.len() == 0{
        [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ]
    }else{
        Sha256::digest(l).into()
    }; 
    
    let y = em[0];
    let masked_seed = &em[1..1+H_LEN];
    let masked_db = &em[1+H_LEN..]; 

    let seed_mask = mgf1(masked_db, H_LEN);
    let mut seed = [0u8; H_LEN]; 
    for i in 0..seed_mask.len(){
        seed[i] = masked_seed[i] ^ seed_mask[i];
    }

    let db_mask = mgf1(&seed, K - H_LEN - 1);
    let mut db = [0u8; K - H_LEN - 1]; 
    for i in 0..db_mask.len(){
        db[i] = masked_db[i] ^ db_mask[i];
    }

    let (ok, msg_idx) = is_db_valid(&db, &l_hash, y); 
    if ok.unwrap_u8() == 0u8 {
        return Err("Decryption failed.".to_string());
    } 

    let m = &db[msg_idx..]; 

    return Ok(m.to_vec()); 


}

pub(crate) fn is_db_valid(db: &[u8], l_hash : &[u8], y: u8) -> (Choice, usize){
    let is_y_zero = y.ct_eq(&0u8);

    let l_hash_prime = &db[0..H_LEN];
    let is_l_hash_valid = l_hash_prime.ct_eq(l_hash); 

    let rest = &db[H_LEN..];  

    let mut found = Choice::from(0u8);
    let mut bad_event = Choice::from(0u8);

    let mut msg_idx = rest.len();
     
    for i in 0..rest.len(){
        let b = rest[i]; 
        let is_zero = b.ct_eq(&0u8); 
        let is_one = b.ct_eq(&0x01u8); 
        
        bad_event |= (!found) & !(is_zero | is_one);  

        let first_occurence = (!found)& is_one; 

        // mutliplexer 
        let c = first_occurence.unwrap_u8() as usize;
        let mask = 0usize.wrapping_sub(c);
        msg_idx = (msg_idx & !mask) | ((i+1) & mask);
        
        found |= is_one;
    }
    
    let mut ok = is_y_zero; 
    ok = ok.bitand(is_l_hash_valid); 
    ok = ok.bitand(found); 
    ok = ok.bitand(!bad_event);
    
    return (ok, H_LEN + msg_idx);
}