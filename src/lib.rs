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

/// A padded input to the SHA256 hash function as a ciphertext
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InputCiphertext {
    inner: Vec<U32Ct>,
}

/// A SHA256 digest as a ciphertext
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DigestCiphertext {
    inner: [U32Ct; 8],
}

fn encrypt_input_helper(message: Vec<u8>, enc: impl Fn(u32) -> U32Ct) -> InputCiphertext {
    // padding
    let message = pad_message(message);
    // encrypt using the client key
    let inner = message
        .into_iter()
        .array_chunks::<4>()
        .map(u32::from_be_bytes)
        .map(enc)
        .collect::<Vec<_>>();
    InputCiphertext { inner }
}

/// Pad and encrypt an input message to be hashed
pub fn encrypt_input(message: Vec<u8>, client_key: &ClientKey) -> InputCiphertext {
    encrypt_input_helper(message, |x| U32Ct::encrypt(x, client_key))
}

/// Pad and trivially encrypt an input message to be hashed. This does not
/// obfuscate the input. Passing the resulting [`InputCiphertext`] into
/// [`sha256_tfhe`] is simply SHA256 evaluation the clear
pub fn trivial_encrypt_input(message: Vec<u8>, server_key: &ServerKey) -> InputCiphertext {
    encrypt_input_helper(message, |x| U32Ct::trivial_encrypt(x, server_key))
}

fn round(alphabet: &mut [U32Ct; 8], kp: &U32Ct, server_key: &ServerKey) {
    let [a, b, c, d, e, f, g, h] = alphabet.get_many_mut([0, 1, 2, 3, 4, 5, 6, 7]).unwrap();
    let t1 = h
        .add(&capsigma1(e, server_key), server_key)
        .add(&ch(e, f, g, server_key), server_key)
        .add(kp, server_key);
    let t2 = capsigma0(a, server_key).add(&maj(a, b, c, server_key), server_key);
    *d = d.add(&t1, server_key);
    *h = t1.add(&t2, server_key);
}

/// Perform SHA256 of an [`InputCiphertext`] fully homomorphically
pub fn sha256_tfhe(input_ct: &InputCiphertext, server_key: &ServerKey) -> DigestCiphertext {
    let input_ct = &input_ct.inner;
    let message_length = input_ct.len();
    let blocks = message_length / 16;
    assert_eq!(message_length % 16, 0);

    let mut input_ct = input_ct.iter();
    let mut s = H.map(|hi| U32Ct::trivial_encrypt(hi, server_key));
    let k = K.map(|ki| U32Ct::trivial_encrypt(ki, server_key));

    for _ in 0..blocks {
        let mut alphabet = s.clone();

        let mut w = array::from_fn::<_, 16, _>(|i| {
            let wi = input_ct.next().unwrap().clone();

            let k_w = k[i].add(&wi, server_key);
            round(&mut alphabet, &k_w, server_key);

            alphabet.rotate_right(1);

            wi
        });

        #[allow(clippy::needless_range_loop)]
        for i in 16..64 {
            let [wo0, wo1, wo9, wo14] =
                w.get_many_mut([i % 16, (i + 1) % 16, (i + 9) % 16, (i + 14) % 16]).unwrap();

            let s0 = sigma0(wo1, server_key);
            let s1 = sigma1(wo14, server_key);

            *wo0 = wo0.add(&s0, server_key).add(&s1, server_key).add(wo9, server_key);

            let k_wo0 = wo0.add(&k[i], server_key);
            round(&mut alphabet, &k_wo0, server_key);

            alphabet.rotate_right(1);
        }

        for (s_i, alphabet_i) in s.iter_mut().zip(alphabet) {
            *s_i = s_i.add(&alphabet_i, server_key);
        }
    }

    DigestCiphertext { inner: s }
}

/// Decrypt a [`DigestCiphertext`] with the same `ClientKey` that encrypted its
/// [`InputCiphertext`]
pub fn decrypt_hash(digest_ct: &DigestCiphertext, client_key: &ClientKey) -> [u8; 32] {
    digest_ct
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
        let input = b"".to_vec();
        let input_ct = trivial_encrypt_input(input.clone(), &server_key);
        let hash_ct = sha256_tfhe(&input_ct, &server_key);
        let hash = decrypt_hash(&hash_ct, &client_key);
        let expected_hash = Sha256::digest(input);
        assert_eq!(&hash, expected_hash.as_slice());
    }

    #[test]
    fn test_small_input_trivial() {
        let (client_key, server_key) = gen_keys();
        let input = b"hello world".to_vec();
        let input_ct = trivial_encrypt_input(input.clone(), &server_key);
        let hash_ct = sha256_tfhe(&input_ct, &server_key);
        let hash = decrypt_hash(&hash_ct, &client_key);
        let expected_hash = Sha256::digest(input);
        assert_eq!(&hash, expected_hash.as_slice());
    }

    #[test]
    fn test_larger_input_trivial() {
        let (client_key, server_key) = gen_keys();
        let input = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".to_vec();
        let input_ct = trivial_encrypt_input(input.clone(), &server_key);
        let hash_ct = sha256_tfhe(&input_ct, &server_key);
        let hash = decrypt_hash(&hash_ct, &client_key);
        let expected_hash = Sha256::digest(input);
        assert_eq!(&hash, expected_hash.as_slice());
    }

    #[test]
    #[ignore]
    fn test_empty_input() {
        let (client_key, server_key) = gen_keys();
        let input = b"".to_vec();
        let input_ct = encrypt_input(input.clone(), &client_key);
        let hash_ct = sha256_tfhe(&input_ct, &server_key);
        let hash = decrypt_hash(&hash_ct, &client_key);
        let expected_hash = Sha256::digest(input);
        assert_eq!(&hash, expected_hash.as_slice());
    }

    #[test]
    #[ignore]
    fn test_small_input() {
        let (client_key, server_key) = gen_keys();
        let input = b"hello world".to_vec();
        let input_ct = encrypt_input(input.clone(), &client_key);
        let hash_ct = sha256_tfhe(&input_ct, &server_key);
        let hash = decrypt_hash(&hash_ct, &client_key);
        let expected_hash = Sha256::digest(input);
        assert_eq!(&hash, expected_hash.as_slice());
    }

    #[test]
    #[ignore]
    fn test_larger_input() {
        let (client_key, server_key) = gen_keys();
        let input = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".to_vec();
        let input_ct = encrypt_input(input.clone(), &client_key);
        let hash_ct = sha256_tfhe(&input_ct, &server_key);
        let hash = decrypt_hash(&hash_ct, &client_key);
        let expected_hash = Sha256::digest(input);
        assert_eq!(&hash, expected_hash.as_slice());
    }
}
