mod rsa; 
mod rsa_pss;
mod rsa_oaep; 
mod common; 

#[cfg(test)]

mod tests {

    use crate::{rsa, rsa_pss, rsa_oaep};
    
    use crypto_bigint::*; 
    
    #[test]
    fn enc_dec_test(){
        let (pk, sk) = rsa::keygen();
        let m = U3072::from_u64(12); 
        let c = rsa::enc(&pk, &m);
        assert_eq!(rsa::dec(&sk, &c), m);
    }

    #[test]
    fn sign_verify_test(){
        let (pk, sk) = rsa::keygen(); 
        let m = U3072::from_u64(12); 
        let s = rsa::sign(&sk, &m);
        assert_eq!(rsa::verify(&pk, &s), m);
    }

    #[test]
    fn rsa_pss_sign_test(){
        let (pk, sk) = rsa_pss::keygen();
        let m = b"67"; 
        let s = rsa_pss::sign(&sk, m); 
        assert!(rsa_pss::verify(&pk, m, &s));
    }

    #[test]
    fn rsa_oaep_enc_dec_test(){
        let (pk, sk) = rsa_oaep::keygen(); 
        let m = b"67"; 
        let l = b"67";
        let c = rsa_oaep::enc(&pk, m, l);
        let m_prime = rsa_oaep::dec(&sk, &c, l);
        assert_eq!(m_prime, m.to_vec());
    }

    fn dummy_hash()-> [u8; 32]{
        [0xAA; 32]
    }

    fn build_db(ps: &[u8], l_hash: &[u8], m: &[u8], delimiter: u8) -> Vec<u8>{
        let mut db = Vec::new();
        db.extend_from_slice(l_hash);
        db.extend_from_slice(ps);
        db.push(delimiter);
        db.extend_from_slice(m);
        return db;
    }

    #[test] 
    fn db_valid_test_empty_ps(){
        let msg = b"msg"; 
        let db = build_db(&[], &dummy_hash(), msg, 0x01); 
        let (ok, idx) = rsa_oaep::is_db_valid(&db, &dummy_hash(), 0);
        assert_eq!(ok.unwrap_u8(), 1u8);
        assert_eq!(idx, 33);
    }

    #[test]
    fn db_valid_test_1(){
        let msg = b"msg"; 
        let ps = [0u8; 10]; 
        let db = build_db(&ps, &dummy_hash(), msg, 0x01); 
        let (ok, idx) = rsa_oaep::is_db_valid(&db, &dummy_hash(), 0);
        assert_eq!(ok.unwrap_u8(), 1u8);
        assert_eq!(idx, 43);
    }

    #[test]
    fn db_valid_test_2(){
        let msg = b"msg"; 
        let ps = [0u8; 10]; 
        let mut db = build_db(&ps, &dummy_hash(), msg, 0x02); 
        let (ok, _) = rsa_oaep::is_db_valid(&db, &dummy_hash(), 0); 
        assert_eq!(ok.unwrap_u8(), 0u8);
    }

    #[test] 
    fn db_valid_test_3(){
        let msg = b"msg"; 
        let mut ps = vec![0u8;5]; 
        ps.push(0x02); 
        ps.extend_from_slice(&[0u8; 5]);

        let mut db = build_db(&ps, &dummy_hash(), msg, 0x01); 
        db[0] = 0xFF; 
        let (ok, _) = rsa_oaep::is_db_valid(&db, &dummy_hash(), 0); 
        assert_eq!(ok.unwrap_u8(), 0u8);

    }

    #[test]
    fn db_valid_test_4(){
        let msg = [0x01, 0x02, 0x03]; 
        let ps = vec![0u8;5]; 
        let db = build_db(&ps, &dummy_hash(), &msg, 0x01);  
        let (ok, idx) = rsa_oaep::is_db_valid(&db, &dummy_hash(), 0);
        assert_eq!(ok.unwrap_u8(), 1u8);
        assert_eq!(idx, 32+5+1);
    } 
}
