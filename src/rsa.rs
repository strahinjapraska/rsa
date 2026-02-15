use crypto_bigint::{Odd, U3072, Zero, modular::{MontyForm, MontyParams}};



pub struct RSAPrivateKey {
    p: U3072, 
    q: U3072, 
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

    return (RSAPublicKey{e, n}, RSAPrivateKey{p, q, d, n});
} 

pub(crate) fn enc(pk: &RSAPublicKey, m: &U3072) -> U3072{
    if m >= &pk.n || m < &U3072::ZERO {
        panic!("Message representative out of range");
    }
    pow_mod(m, &pk.e, &pk.n)
}

pub(crate) fn sign(sk: &RSAPrivateKey, m: &U3072) -> U3072{
    if m >= &sk.n || m < &U3072::ZERO {
        panic!("Message representative out of range");
    }
    pow_mod(m, &sk.d, &sk.n)
}

pub fn verify(pk: &RSAPublicKey, s: &U3072) -> U3072{
    if s >= &pk.n || s < &U3072::ZERO {
        panic!("Signature representative out of range");
    }
    pow_mod(s, &pk.e, &pk.n) 
}

pub fn dec(sk: &RSAPrivateKey, c: &U3072) -> U3072{
    if c >= &sk.n || c < &U3072::ZERO {
        panic!("Ciphertext representative out of range");
    }
    pow_mod(&c, &sk.d, &sk.n)
} 

fn pow_mod(base: &U3072, exponent: &U3072, modulus: &U3072) -> U3072{
    let n = Odd::new(*modulus).expect("Invalid modulus");
    let params = MontyParams::new(n); 

    let monty_base = MontyForm::new(base, params); 
    let result = monty_base.pow(&exponent);
    
    result.retrieve()

}
