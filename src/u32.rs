use std::mem::{self, MaybeUninit};

use tfhe::shortint::{Ciphertext, ClientKey};

pub struct U32Ct {
    inner: [Ciphertext; 8], // least significant short first
}

impl U32Ct {
    pub fn encrypt(mut x: u32, client_key: &ClientKey) -> Self {
        let mut inner: [MaybeUninit<Ciphertext>; 8] =
            unsafe { MaybeUninit::uninit().assume_init() };
        for elem in &mut inner[..] {
            let nibble = x & 0b1111;
            x >>= 4;
            let short = client_key.encrypt(nibble.into());
            elem.write(short);
        }
        let inner = unsafe { mem::transmute::<_, [Ciphertext; 8]>(inner) };
        Self { inner }
    }

    pub fn decrypt(&self, client_key: &ClientKey) -> u32 {
        let mut plaintext = 0;
        for short in self.inner.iter().rev() {
            plaintext <<= 4;
            let nibble = client_key.decrypt(&short) as u32;
            plaintext |= nibble;
        }
        plaintext
    }

    // add/add scalar
    // rotate left/right by scalar
    // bitxor, bitand, bitneg,
}

#[cfg(test)]
mod tests {
    use tfhe::shortint::parameters;

    use super::*;

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
}
