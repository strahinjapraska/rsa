use crypto_bigint::{Odd, U3072, Zero, modular::{MontyForm, MontyParams}};



pub struct RSAPrivateKey {
    d: U3072, 
    n: U3072,
}
pub struct RSAPublicKey {
    e: U3072, 
    n: U3072,
}

pub(crate) fn keygen() -> (RSAPublicKey, RSAPrivateKey) {
    let p = crypto_primes::generate_prime::<U3072>(1536); 
    let q = crypto_primes::generate_prime::<U3072>(1536);    
    let n = p*q; 

    let e = U3072::from_u32(65537);
    let phi = (p-U3072::ONE)*(q-U3072::ONE); 
    let d = e.inv_mod(&phi).expect("Failed to generate keys"); 

    return (RSAPublicKey{e, n}, RSAPrivateKey{d, n});
} 

pub(crate) fn enc(pk: &RSAPublicKey, m: &U3072) -> Result<U3072, String>{
    if m >= &pk.n || m < &U3072::ZERO {
        Err("message repsresentative out of the range".to_string())
    }else{
        Ok(pow_mod(m, &pk.e, &pk.n))
    }
}
pub fn dec(sk: &RSAPrivateKey, c: &U3072) -> Result<U3072, String>{
    if c >= &sk.n || c < &U3072::ZERO {
        Err("ciphertext representative out of range".to_string())
    }else{
        Ok(pow_mod(&c, &sk.d, &sk.n)) 
    }
    
} 

pub(crate) fn sign(sk: &RSAPrivateKey, m: &U3072) -> Result<U3072, String>{
    dec(sk, m)
}

pub fn verify(pk: &RSAPublicKey, s: &U3072) -> Result<U3072, String>{
    enc(pk, s)
}



fn pow_mod(base: &U3072, exponent: &U3072, modulus: &U3072) -> U3072{
    let n = Odd::new(*modulus).expect("Invalid modulus");
    let params = MontyParams::new(n); 

    let monty_base = MontyForm::new(base, params); 
    let result = monty_base.pow(&exponent);
    
    result.retrieve()

}
