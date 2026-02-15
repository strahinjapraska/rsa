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
        rsa_oaep::enc(&pk, m, l);
    }
}
