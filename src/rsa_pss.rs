use std::vec;
use crypto_bigint::{U3072};
use rand::RngCore;
use crate::{common::*, rsa::{self, RSAPrivateKey}};
use sha2::{Digest, Sha256};
use crate::common::mgf1; 



pub fn keygen() -> (rsa::RSAPublicKey, rsa::RSAPrivateKey) {
    rsa::keygen()
}

pub fn sign(sk: &RSAPrivateKey, m: &[u8]) -> [u8; 384]{
    let em = emsa_pss_encode(m); 
    let m = U3072::from_be_slice(&em);  
    let s = rsa::sign(sk, &m);  
    return s.to_be_bytes();
}

pub fn verify(pk: &rsa::RSAPublicKey, m: &[u8], s: &[u8]) -> bool{
    if s.len() != K{
        return false; 
    }
    let s = U3072::from_be_slice(s);
    let m_prime = rsa::verify(pk, &s); 
    let em = m_prime.to_be_bytes();
    emsa_pss_verify(m, &em)
}

fn emsa_pss_encode(m: &[u8]) -> [u8; EM_LEN]{
    assert!((m.len() as u64) <= 2u64.pow(61) - 1); 

    let m_hash = Sha256::digest(m); 

    assert!(EM_LEN >= H_LEN + SALT_LEN + 2); 

    let mut salt = [0u8; SALT_LEN]; 
    rand::rng().fill_bytes(&mut salt);

    let mut m_prime = [0u8; 8 + H_LEN + SALT_LEN]; 
    m_prime[8..8+H_LEN].copy_from_slice(&m_hash);
    m_prime[8+H_LEN..].copy_from_slice(&salt); 

    let h = Sha256::digest(&m_prime);

    let ps_len = EM_LEN - SALT_LEN - H_LEN - 2;
    
    let ps = vec![0u8; ps_len]; 

    let mut db = [0u8; EM_LEN - H_LEN - 1]; 
    db[..ps_len].copy_from_slice(&ps);
    db[ps_len] = 0x01;
    db[ps_len+1..].copy_from_slice(&salt); 

    let mut db_mask = mgf1(h.as_slice(), EM_LEN - H_LEN - 1);

    for (x, y) in db_mask.iter_mut().zip(db.iter()){
        *x ^= *y;
    } 

    db_mask[0] &= 0x7F; 

    let mut em = [0u8; EM_LEN]; 
    em[..db_mask.len()].copy_from_slice(&db_mask);
    em[db_mask.len()..EM_LEN -1].copy_from_slice(h.as_slice());
    em[EM_LEN - 1] = 0xBC;

    em 

}

fn emsa_pss_verify(m: &[u8], em: &[u8]) -> bool{
    assert!((m.len() as u64) <= 2u64.pow(61) - 1); 

    let m_hash = Sha256::digest(m); 

    assert!(EM_LEN >= H_LEN + SALT_LEN + 2); 

    if em[EM_LEN - 1] != 0xBC {
        return false; 
    }

    let masked_db = &em[..EM_LEN - H_LEN - 1]; 
    let h = &em[EM_LEN - H_LEN - 1..EM_LEN - 1]; 

    if masked_db[0] & 0x80 != 0 {
        return false; 
    } 

    let db_mask = mgf1(h, EM_LEN - H_LEN - 1); 

    let mut db = vec![0u8; masked_db.len()]; 

    for i in 0..masked_db.len(){
        db[i] = masked_db[i] ^ db_mask[i];
    }

    db[0] &= 0x7F; 

    let ps_len = EM_LEN - SALT_LEN - H_LEN - 2; 
    if db[..ps_len].iter().any(|&x| x != 0) {
        return false; 
    } 
    if db[ps_len] != 0x01 {
        return false; 
    }

    let salt = &db[ps_len + 1..]; 

    let mut m_prime = [0u8; 8 + H_LEN + SALT_LEN]; 
    m_prime[8..8+H_LEN].copy_from_slice(&m_hash);
    m_prime[8+H_LEN..].copy_from_slice(salt); 

    let h_prime = Sha256::digest(&m_prime); 

    if h_prime.as_slice() != h {
        return false; 
    }

    return true; 
}

