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

    pub fn trivial_encrypt(x: u32, server_key: &ServerKey) -> Self {
        let inner = bits(x).map(|b| server_key.trivial_encrypt(b));
        Self { inner }
    }

    pub fn decrypt(&self, client_key: &ClientKey) -> u32 {
        from_bits(self.inner.each_ref().map(|b| client_key.decrypt(b)))
    }

    pub fn add(&self, other: &Self, server_key: &ServerKey) -> Self {
        let mut carry = server_key.trivial_encrypt(false);
        let inner = self.inner.each_ref().zip(other.inner.each_ref()).map(|(a, b)| {
            let s;
            (s, carry) = full_adder(a, b, &carry, server_key);
            s
        });
        Self { inner }
    }

    pub fn add_scalar(&self, other: u32, server_key: &ServerKey) -> Self {
        let other_trivial = Self::trivial_encrypt(other, server_key);
        self.add(&other_trivial, server_key)
    }

    pub fn bitxor(&self, other: &Self, server_key: &ServerKey) -> Self {
        let inner =
            self.inner.each_ref().zip(other.inner.each_ref()).map(|(l, r)| server_key.xor(l, r));
        Self { inner }
    }

    pub fn bitxor_scalar(&self, other: u32, server_key: &ServerKey) -> Self {
        let other_trivial = Self::trivial_encrypt(other, server_key);
        self.bitxor(&other_trivial, server_key)
    }

    pub fn bitand(&self, other: &Self, server_key: &ServerKey) -> Self {
        let inner =
            self.inner.each_ref().zip(other.inner.each_ref()).map(|(l, r)| server_key.and(l, r));
        Self { inner }
    }

    pub fn bitand_scalar(&self, other: u32, server_key: &ServerKey) -> Self {
        let other_trivial = Self::trivial_encrypt(other, server_key);
        self.bitand(&other_trivial, server_key)
    }

    pub fn bitnot(&self, server_key: &ServerKey) -> Self {
        let inner = self.inner.each_ref().map(|b| server_key.not(b));
        Self { inner }
    }

    pub fn rotate_right(&self, shift: usize) -> Self {
        // rotating the integer right requires moving ciphertexts left
        let mut inner = self.inner.clone();
        inner.rotate_left(shift);
        Self { inner }
    }

    pub fn shift_right(&self, shift: usize, server_key: &ServerKey) -> Self {
        // shifting the integer right requires moving ciphertexts left
        let mut inner = self.inner.clone();
        inner.rotate_left(shift);
        for i in 0..shift {
            inner[31 - i] = server_key.trivial_encrypt(false);
        }
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

fn full_adder(
    a: &Ciphertext,
    b: &Ciphertext,
    c_in: &Ciphertext,
    server_key: &ServerKey,
) -> (Ciphertext, Ciphertext) {
    let a_xor_b = server_key.xor(a, b);
    let s = server_key.xor(&a_xor_b, c_in);
    let axb_and_c_in = server_key.and(&a_xor_b, c_in);
    let a_and_b = server_key.and(a, b);
    let c_out = server_key.or(&axb_and_c_in, &a_and_b);
    (s, c_out)
}

#[cfg(test)]
mod tests {
    use tfhe::boolean::gen_keys;

    use super::*;

    #[test]
    fn test_bits() {
        let bits = bits(0x234928fc);
        let n = from_bits(bits);
        assert_eq!(n, 0x234928fc);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let (key, _) = gen_keys();
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
        let ct = U32Ct::encrypt(3472387250, &client_key);
        let r = ct.bitxor_scalar(964349245, &server_key);
        let pt = r.decrypt(&client_key);
        assert_eq!(pt, 3472387250 ^ 964349245);
    }

    #[test]
    fn test_bitand() {
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

    #[test]
    fn test_rotate_right() {
        let (key, _) = gen_keys();
        let ct = U32Ct::encrypt(3472387250, &key);
        let r = ct.rotate_right(12);
        let pt = r.decrypt(&key);
        assert_eq!(pt, 3472387250u32.rotate_right(12));
    }

    #[test]
    fn test_shift_right() {
        let (client_key, server_key) = gen_keys();
        let ct = U32Ct::encrypt(3472387250, &client_key);
        let r = ct.shift_right(12, &server_key);
        let pt = r.decrypt(&client_key);
        assert_eq!(pt, 3472387250u32 >> 12);
    }

    #[test]
    fn test_full_adder() {
        let (client_key, server_key) = gen_keys();
        let assert_instance = |a, b, c_in, s_expected, c_out_expected| {
            let a = client_key.encrypt(a);
            let b = client_key.encrypt(b);
            let c_in = client_key.encrypt(c_in);
            let (s, c_out) = full_adder(&a, &b, &c_in, &server_key);
            let s = client_key.decrypt(&s);
            let c_out = client_key.decrypt(&c_out);
            assert_eq!(s_expected, s);
            assert_eq!(c_out_expected, c_out);
        };
        assert_instance(false, false, false, false, false);
        assert_instance(false, false, true, true, false);
        assert_instance(false, true, false, true, false);
        assert_instance(false, true, true, false, true);
        assert_instance(true, false, false, true, false);
        assert_instance(true, false, true, false, true);
        assert_instance(true, true, false, false, true);
        assert_instance(true, true, true, true, true);
    }

    #[test]
    fn test_add() {
        let (client_key, server_key) = gen_keys();
        let ct1 = U32Ct::encrypt(33, &client_key);
        let r = ct1.add_scalar(36, &server_key);
        let pt = r.decrypt(&client_key);
        assert_eq!(pt, 33u32.wrapping_add(36));
        let ct1 = U32Ct::encrypt(3472387250, &client_key);
        let r = ct1.add_scalar(964349245, &server_key);
        let pt = r.decrypt(&client_key);
        assert_eq!(pt, 3472387250u32.wrapping_add(964349245));
    }
}
