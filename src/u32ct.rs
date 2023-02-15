use tfhe::shortint::{Ciphertext, ClientKey, ServerKey};

// TODO: parallelize many of the for loops here with rayon

pub struct U32Ct {
    inner: [Ciphertext; 8], // least significant nibble first
}

impl U32Ct {
    pub fn encrypt(x: u32, client_key: &ClientKey) -> Self {
        let inner = nibbles(x).map(|n| client_key.encrypt(n.into()));
        Self { inner }
    }

    pub fn decrypt(&self, client_key: &ClientKey) -> u32 {
        let mut plaintext = 0;
        for short in self.inner.iter().rev() {
            plaintext <<= 4;
            let nibble = client_key.decrypt(short) as u32;
            plaintext |= nibble;
        }
        plaintext
    }

    // pub fn add(&mut self, other: &mut Self, server_key: &ServerKey) -> Self {
    //     let r0 = server_key.unchecked_bitxor(&mut self.inner[0], &mut other.inner[0]);
    //     let carry = server_key.carry_extract(&r0);
    //     todo!()
    // }

    // pub fn add_scalar(&self, mut other: u32, server_key: &ServerKey) -> Self {
    //     todo!()
    // }

    pub fn bitxor(&mut self, other: &mut Self, server_key: &ServerKey) -> Self {
        let inner = self
            .inner
            .each_mut()
            .zip(other.inner.each_mut())
            .map(|(l, r)| server_key.smart_bitxor(l, r));
        Self { inner }
    }

    pub fn bitxor_scalar(&self, other: u32, server_key: &ServerKey) -> Self {
        let ops = nibbles(other).map(|n| Box::new(move |x| x ^ (n as u64)) as _);
        self.unary_op_per_nibble_unique(ops, server_key)
    }

    pub fn bitand(&mut self, other: &mut Self, server_key: &ServerKey) -> Self {
        let inner = self
            .inner
            .each_mut()
            .zip(other.inner.each_mut())
            .map(|(l, r)| server_key.smart_bitand(l, r));
        Self { inner }
    }

    pub fn bitand_scalar(&self, other: u32, server_key: &ServerKey) -> Self {
        let ops = nibbles(other).map(|n| Box::new(move |x| x & (n as u64)) as _);
        self.unary_op_per_nibble_unique(ops, server_key)
    }

    // TODO: rotate left/right by scalar

    pub fn bitnot(&self, server_key: &ServerKey) -> Self {
        self.unary_op_per_nibble(|x| !x, server_key)
    }

    #[inline]
    fn unary_op_per_nibble_unique(
        &self,
        ops: [Box<dyn Fn(u64) -> u64>; 8],
        server_key: &ServerKey,
    ) -> Self {
        let inner = self.inner.each_ref().zip(ops).map(|(nib, op)| {
            let acc = server_key.generate_accumulator(&op);
            server_key.keyswitch_programmable_bootstrap(nib, &acc)
        });
        Self { inner }
    }

    #[inline]
    fn unary_op_per_nibble(&self, op: impl Fn(u64) -> u64, server_key: &ServerKey) -> Self {
        let acc = server_key.generate_accumulator(op);
        let inner = self
            .inner
            .each_ref()
            .map(|nib| server_key.keyswitch_programmable_bootstrap(nib, &acc));
        Self { inner }
    }
}

fn nibbles(mut x: u32) -> [u32; 8] {
    [0u32; 8].map(|_| {
        let nibble = x & 0b1111;
        x >>= 4;
        nibble
    })
}

#[cfg(test)]
mod tests {
    use tfhe::shortint::{gen_keys, parameters};

    use super::*;

    #[test]
    fn test_nibbles() {
        let nibbles = nibbles(0x234928fc);
        assert_eq!(nibbles, [0xc, 0xf, 0x8, 0x2, 0x9, 0x4, 0x3, 0x2]);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = ClientKey::new(parameters::PARAM_MESSAGE_4_CARRY_1);
        let ct = U32Ct::encrypt(0, &key);
        let pt = ct.decrypt(&key);
        assert_eq!(pt, 0);
        let ct = U32Ct::encrypt(234353, &key);
        let pt = ct.decrypt(&key);
        assert_eq!(pt, 234353);
    }

    #[test]
    fn test_bitxor() {
        let (client_key, server_key) = gen_keys(parameters::PARAM_MESSAGE_4_CARRY_1);
        let mut ct1 = U32Ct::encrypt(4206143820, &client_key);
        let mut ct2 = U32Ct::encrypt(234252, &client_key);
        let r = ct1.bitxor(&mut ct2, &server_key);
        let pt = r.decrypt(&client_key);
        assert_eq!(pt, 4206143820 ^ 234252);
    }

    #[test]
    fn test_bitxor_scalar() {
        let (client_key, server_key) = gen_keys(parameters::PARAM_MESSAGE_4_CARRY_1);
        let ct = U32Ct::encrypt(4206143820, &client_key);
        let r = ct.bitxor_scalar(234252, &server_key);
        let pt = r.decrypt(&client_key);
        assert_eq!(pt, 4206143820 ^ 234252);
    }

    #[test]
    fn test_bitand() {
        let (client_key, server_key) = gen_keys(parameters::PARAM_MESSAGE_4_CARRY_1);
        let mut ct1 = U32Ct::encrypt(4206143820, &client_key);
        let mut ct2 = U32Ct::encrypt(234252, &client_key);
        let r = ct1.bitand(&mut ct2, &server_key);
        let pt = r.decrypt(&client_key);
        let a = 4206143820u32;
        let b = 234252u32;
        let c = 256u32;
        let d = 4206312000u32;
        println!("{a:b}\n{b:b}\n{c:b}\n{d:b}\n");
        assert_eq!(pt, 4206143820 & 234252);
    }

    #[test]
    fn test_bitand_scalar() {
        let (client_key, server_key) = gen_keys(parameters::PARAM_MESSAGE_4_CARRY_1);
        let ct = U32Ct::encrypt(4206143820, &client_key);
        let r = ct.bitand_scalar(234252, &server_key);
        let pt = r.decrypt(&client_key);
        assert_eq!(pt, 4206143820 & 234252);
    }

    #[test]
    fn test_bitnot() {
        let (client_key, server_key) = gen_keys(parameters::PARAM_MESSAGE_4_CARRY_1);
        let ct = U32Ct::encrypt(4206143820, &client_key);
        let r = ct.bitnot(&server_key);
        let pt = r.decrypt(&client_key);
        assert_eq!(pt, !4206143820);
    }
}
