#![feature(array_methods, array_zip, iter_array_chunks)]

mod constants;
mod u32ct;
mod util;

use std::array;

use serde::{Deserialize, Serialize};
use tfhe::boolean::{client_key::ClientKey, server_key::ServerKey};

use constants::*;
use u32ct::*;
use util::*;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PreimageCt {
    inner: Vec<U32Ct>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HashCt {
    inner: [U32Ct; 8],
}

pub fn encrypt_preimage(mut message: Vec<u8>, client_key: &ClientKey) -> PreimageCt {
    // padding
    let length = message.len() as u64;
    message.push(0x80);
    while (message.len() * 8 + 64) % 512 != 0 {
        message.push(0x00);
    }
    let len_be_bytes = length.to_be_bytes();
    message.extend(&len_be_bytes);
    assert_eq!((message.len() * 8) % 512, 0);
    // encrypt using the client key
    let inner = message
        .into_iter()
        .array_chunks::<4>()
        .map(u32::from_be_bytes)
        .map(|x| U32Ct::encrypt(x, client_key))
        .collect::<Vec<_>>();
    PreimageCt { inner }
}

pub fn sha256_tfhe(preimage_ct: &PreimageCt, server_key: &ServerKey) -> HashCt {
    let preimage_ct = &preimage_ct.inner;
    let message_length = preimage_ct.len();
    assert_eq!(message_length % 16, 0);
    let blocks = message_length / 16;

    let mut preimage_index = 0;

    let mut h0 = U32Ct::trivial_encrypt(H[0], server_key);
    let mut h1 = U32Ct::trivial_encrypt(H[1], server_key);
    let mut h2 = U32Ct::trivial_encrypt(H[2], server_key);
    let mut h3 = U32Ct::trivial_encrypt(H[3], server_key);
    let mut h4 = U32Ct::trivial_encrypt(H[4], server_key);
    let mut h5 = U32Ct::trivial_encrypt(H[5], server_key);
    let mut h6 = U32Ct::trivial_encrypt(H[6], server_key);
    let mut h7 = U32Ct::trivial_encrypt(H[7], server_key);

    for asdf in 0..blocks {
        println!("asdf: {asdf}");

        let mut a = h0.clone();
        let mut b = h1.clone();
        let mut c = h2.clone();
        let mut d = h3.clone();
        let mut e = h4.clone();
        let mut f = h5.clone();
        let mut g = h6.clone();
        let mut h = h7.clone();

        let mut x = array::from_fn::<_, 16, _>(|i| {
            println!("i: {i}");
            let xi = &preimage_ct[preimage_index];
            preimage_index += 1;

            let mut t1 = h.clone();
            t1 = t1.add(&capsigma1(&e, server_key), server_key);
            t1 = t1.add(&ch(&e, &f, &g, server_key), server_key);
            t1 = t1.add(&U32Ct::trivial_encrypt(K[i], server_key), server_key);
            t1 = t1.add(xi, server_key);

            let mut t2 = capsigma0(&a, server_key);
            t2 = t2.add(&maj(&a, &b, &c, server_key), server_key);

            h = g.clone();
            g = f.clone();
            f = e.clone();
            e = d.add(&t1, server_key);
            d = c.clone();
            c = b.clone();
            b = a.clone();
            a = t1.add(&t2, server_key);

            xi.clone()
        });

        for i in 0..64 {
            println!("i: {i}");
            let mut s0 = x[(i + 1) & 0x0f].clone();
            s0 = sigma0(&s0, server_key);
            let mut s1 = x[(i + 14) & 0x0f].clone();
            s1 = sigma1(&s1, server_key);

            x[i & 0xf] = x[i & 0xf]
                .add(&s0, server_key)
                .add(&s1, server_key)
                .add(&x[(i + 9) & 0xf], server_key);
            let t1 = x[i & 0xf]
                .add(&h, server_key)
                .add(&capsigma1(&e, server_key), server_key)
                .add(&ch(&e, &f, &g, server_key), server_key)
                .add(&U32Ct::trivial_encrypt(K[i], server_key), server_key);
            let t2 = capsigma0(&a, server_key).add(&maj(&a, &b, &c, server_key), server_key);

            h = g.clone();
            g = f.clone();
            f = e.clone();
            e = d.add(&t1, server_key);
            d = c;
            c = b;
            b = a;
            a = t1.add(&t2, server_key);
        }

        h0 = h0.add(&a, server_key);
        h1 = h1.add(&b, server_key);
        h2 = h2.add(&c, server_key);
        h3 = h3.add(&d, server_key);
        h4 = h4.add(&e, server_key);
        h5 = h5.add(&f, server_key);
        h6 = h6.add(&g, server_key);
        h7 = h7.add(&h, server_key);
    }

    HashCt { inner: [h0, h1, h2, h3, h4, h5, h6, h7] }
}

pub fn decrypt_hash(hash_ct: &HashCt, client_key: &ClientKey) -> [u8; 32] {
    hash_ct
        .inner
        .iter()
        .map(|ct| ct.decrypt(client_key))
        .map(u32::to_be_bytes)
        .flatten()
        .collect::<Vec<_>>()
        .try_into()
        .expect("to flatten into [u8; 32]")
}

#[cfg(test)]
mod tests {
    use sha2::{Sha256, Digest};
    use tfhe::boolean::gen_keys;

    use super::*;

    #[test]
    fn test_empty_input() {
        let (client_key, server_key) = gen_keys();
        let preimage = b"".to_vec();
        let preimage_ct = encrypt_preimage(preimage.clone(), &client_key);
        let hash_ct = sha256_tfhe(&preimage_ct, &server_key);
        let hash = decrypt_hash(&hash_ct, &client_key);
        let expected_hash = Sha256::digest(preimage);
        assert_eq!(&hash, expected_hash.as_slice());
    }

    #[test]
    fn test_larger_input() {
        todo!()
    }
}
