use tfhe::boolean::{
    ciphertext::Ciphertext,
    client_key::ClientKey,
    server_key::{BinaryBooleanGates, ServerKey},
};

pub struct U32Ct {
    inner: [Ciphertext; 32], // least significant bit
}

impl U32Ct {
    pub fn encrypt(x: u32, client_key: &ClientKey) -> Self {
        let inner = bits(x).map(|n| client_key.encrypt(n));
        Self { inner }
    }

    pub fn decrypt(&self, client_key: &ClientKey) -> u32 {
        from_bits(self.inner.each_ref().map(|b| client_key.decrypt(b)))
    }

    // pub fn add(&mut self, other: &mut Self, server_key: &ServerKey) -> Self {
    //     let r0 = server_key.unchecked_bitxor(&mut self.inner[0], &mut
    // other.inner[0]);     let carry = server_key.carry_extract(&r0);
    //     todo!()
    // }

    // pub fn add_scalar(&self, mut other: u32, server_key: &ServerKey) -> Self {
    //     todo!()
    // }

    pub fn bitxor(&self, other: &Self, server_key: &ServerKey) -> Self {
        let inner =
            self.inner.each_ref().zip(other.inner.each_ref()).map(|(l, r)| server_key.xor(l, r));
        Self { inner }
    }

    pub fn bitxor_scalar(&self, other: u32, server_key: &ServerKey) -> Self {
        let inner = bits(other).map(|b| server_key.trivial_encrypt(b));
        let other = Self { inner };
        self.bitxor(&other, server_key)
    }

    pub fn bitand(&self, other: &Self, server_key: &ServerKey) -> Self {
        let inner =
            self.inner.each_ref().zip(other.inner.each_ref()).map(|(l, r)| server_key.and(l, r));
        Self { inner }
    }

    pub fn bitand_scalar(&self, other: u32, server_key: &ServerKey) -> Self {
        let inner = bits(other).map(|b| server_key.trivial_encrypt(b));
        let other = Self { inner };
        self.bitand(&other, server_key)
    }

    // TODO: rotate left/right by scalar

    pub fn bitnot(&self, server_key: &ServerKey) -> Self {
        let inner = self.inner.each_ref().map(|b| server_key.not(b));
        Self { inner }
    }
}

fn bits(mut x: u32) -> [bool; 32] {
    [false; 32].map(|_| {
        let bit = (x & 1) == 1;
        x >>= 1;
        bit
    })
}

fn from_bits(bits: [bool; 32]) -> u32 {
    let mut r = 0;
    for b in bits.into_iter().rev() {
        r <<= 1;
        r += b as u32;
    }
    r
}

#[cfg(test)]
mod tests {
    use tfhe::boolean::{gen_keys, parameters};

    use super::*;

    #[test]
    fn test_bits() {
        let bits = bits(0x234928fc);
        let n = from_bits(bits);
        assert_eq!(n, 0x234928fc);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = ClientKey::new(&parameters::DEFAULT_PARAMETERS);
        let ct = U32Ct::encrypt(0, &key);
        let pt = ct.decrypt(&key);
        assert_eq!(pt, 0);
        let ct = U32Ct::encrypt(234353, &key);
        let pt = ct.decrypt(&key);
        assert_eq!(pt, 234353);
    }

    #[test]
    fn test_bitxor() {
        let (client_key, server_key) = gen_keys();
        let ct1 = U32Ct::encrypt(3472387250, &client_key);
        let ct2 = U32Ct::encrypt(964349245, &client_key);
        let r = ct1.bitxor(&ct2, &server_key);
        let pt = r.decrypt(&client_key);
        assert_eq!(pt, 3472387250 ^ 964349245);
    }

    #[test]
    fn test_bitxor_scalar() {
        let (client_key, server_key) = gen_keys();
        let ct = U32Ct::encrypt(3472387250, &client_key);
        let r = ct.bitxor_scalar(964349245, &server_key);
        let pt = r.decrypt(&client_key);
        assert_eq!(pt, 3472387250 ^ 964349245);
    }

    #[test]
    fn test_bitand() {
        let (client_key, server_key) = gen_keys();
        let ct1 = U32Ct::encrypt(3472387250, &client_key);
        let ct2 = U32Ct::encrypt(964349245, &client_key);
        let r = ct1.bitand(&ct2, &server_key);
        let pt = r.decrypt(&client_key);
        let a = 3472387250u32;
        let b = 964349245u32;
        let c = 15728880u32;
        let d = 4206312000u32;
        println!("{a:b}\n{b:b}\n{c:b}\n{d:b}\n");
        assert_eq!(pt, 3472387250 & 964349245);
    }

    #[test]
    fn test_bitand_scalar() {
        let (client_key, server_key) = gen_keys();
        let ct = U32Ct::encrypt(3472387250, &client_key);
        let r = ct.bitand_scalar(964349245, &server_key);
        let pt = r.decrypt(&client_key);
        assert_eq!(pt, 3472387250 & 964349245);
    }

    #[test]
    fn test_bitnot() {
        let (client_key, server_key) = gen_keys();
        let ct = U32Ct::encrypt(3472387250, &client_key);
        let r = ct.bitnot(&server_key);
        let pt = r.decrypt(&client_key);
        assert_eq!(pt, !3472387250);
    }
}
