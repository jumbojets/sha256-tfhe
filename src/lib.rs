#![feature(array_methods, array_zip, get_many_mut, iter_array_chunks)]

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

pub fn encrypt_preimage(message: Vec<u8>, client_key: &ClientKey) -> PreimageCt {
    // padding
    let message = pad_message(message);
    // encrypt using the client key
    let inner = message
        .into_iter()
        .array_chunks::<4>()
        .map(u32::from_be_bytes)
        .map(|x| U32Ct::encrypt(x, client_key))
        .collect::<Vec<_>>();
    PreimageCt { inner }
}

pub fn trivial_encrypt_preimage(message: Vec<u8>, server_key: &ServerKey) -> PreimageCt {
    // padding
    let message = pad_message(message);
    // encrypt using the client key
    let inner = message
        .into_iter()
        .array_chunks::<4>()
        .map(u32::from_be_bytes)
        .map(|x| U32Ct::trivial_encrypt(x, server_key))
        .collect::<Vec<_>>();
    PreimageCt { inner }
}

#[inline]
fn round(alphabet: &mut [U32Ct; 8], k: &U32Ct, server_key: &ServerKey) {
    let [a, b, c, d, e, f, g, h] = alphabet.get_many_mut([0, 1, 2, 3, 4, 5, 6, 7]).unwrap();
    let t1 = h
        .add(&capsigma1(e, server_key), server_key)
        .add(&ch(e, f, g, server_key), server_key)
        .add(k, server_key);
    let t2 = capsigma0(a, server_key).add(&maj(a, b, c, server_key), server_key);
    *d = d.add(&t1, server_key);
    *h = t1.add(&t2, server_key);
}

pub fn sha256_tfhe(preimage_ct: &PreimageCt, server_key: &ServerKey) -> HashCt {
    let preimage_ct = &preimage_ct.inner;
    let message_length = preimage_ct.len();
    assert_eq!(message_length % 16, 0);
    let blocks = message_length / 16;

    let mut preimage_ct = preimage_ct.iter();

    let mut s = H.map(|hi| U32Ct::trivial_encrypt(hi, server_key));
    let k = K.map(|ki| U32Ct::trivial_encrypt(ki, server_key));

    for _ in 0..blocks {
        let mut alphabet = s.clone();

        let mut w = array::from_fn::<_, 16, _>(|i| {
            let wi = preimage_ct.next().unwrap();

            let k = k[i].add(&wi, server_key);
            round(&mut alphabet, &k, server_key);

            alphabet.rotate_right(1);

            wi.clone()
        });

        for i in 16..64 {
            let [wo0, wo1, wo9, wo14] =
                w.get_many_mut([i % 16, (i + 1) % 16, (i + 9) % 16, (i + 14) % 16]).unwrap();

            let s0 = sigma0(wo1, server_key);
            let s1 = sigma1(wo14, server_key);

            *wo0 = wo0
                .add(&s0, server_key)
                .add(&s1, server_key)
                .add(wo9, server_key)
                .add(&k[i], server_key);

            round(&mut alphabet, wo0, server_key);

            alphabet.rotate_right(1);
        }

        for (s_i, alphabet_i) in s.iter_mut().zip(alphabet) {
            *s_i = s_i.add(&alphabet_i, server_key);
        }
    }

    HashCt { inner: s }
}

pub fn decrypt_hash(hash_ct: &HashCt, client_key: &ClientKey) -> [u8; 32] {
    hash_ct
        .inner
        .iter()
        .map(|ct| ct.decrypt(client_key))
        .flat_map(u32::to_be_bytes)
        .collect::<Vec<_>>()
        .try_into()
        .expect("to flatten into [u8; 32]")
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};
    use tfhe::boolean::gen_keys;

    use super::*;

    #[test]
    fn test_empty_input_trivial() {
        let (client_key, server_key) = gen_keys();
        let preimage = b"".to_vec();
        let preimage_ct = trivial_encrypt_preimage(preimage.clone(), &server_key);
        let hash_ct = sha256_tfhe(&preimage_ct, &server_key);
        let hash = decrypt_hash(&hash_ct, &client_key);
        let expected_hash = Sha256::digest(preimage);
        assert_eq!(&hash, expected_hash.as_slice());
    }

    #[test]
    fn test_small_input_trivial() {
        let (client_key, server_key) = gen_keys();
        let preimage = b"hello world".to_vec();
        let preimage_ct = trivial_encrypt_preimage(preimage.clone(), &server_key);
        let hash_ct = sha256_tfhe(&preimage_ct, &server_key);
        let hash = decrypt_hash(&hash_ct, &client_key);
        let expected_hash = Sha256::digest(preimage);
        assert_eq!(&hash, expected_hash.as_slice());
    }

    #[test]
    fn test_larger_input_trivial() {
        let (client_key, server_key) = gen_keys();
        let preimage = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".to_vec();
        let preimage_ct = trivial_encrypt_preimage(preimage.clone(), &server_key);
        let hash_ct = sha256_tfhe(&preimage_ct, &server_key);
        let hash = decrypt_hash(&hash_ct, &client_key);
        let expected_hash = Sha256::digest(preimage);
        assert_eq!(&hash, expected_hash.as_slice());
    }

    #[test]
    #[ignore]
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
    #[ignore]
    fn test_small_input() {
        let (client_key, server_key) = gen_keys();
        let preimage = b"hello world".to_vec();
        let preimage_ct = encrypt_preimage(preimage.clone(), &client_key);
        let hash_ct = sha256_tfhe(&preimage_ct, &server_key);
        let hash = decrypt_hash(&hash_ct, &client_key);
        let expected_hash = Sha256::digest(preimage);
        assert_eq!(&hash, expected_hash.as_slice());
    }

    #[test]
    #[ignore]
    fn test_larger_input() {
        let (client_key, server_key) = gen_keys();
        let preimage = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".to_vec();
        let preimage_ct = encrypt_preimage(preimage.clone(), &client_key);
        let hash_ct = sha256_tfhe(&preimage_ct, &server_key);
        let hash = decrypt_hash(&hash_ct, &client_key);
        let expected_hash = Sha256::digest(preimage);
        assert_eq!(&hash, expected_hash.as_slice());
    }
}
