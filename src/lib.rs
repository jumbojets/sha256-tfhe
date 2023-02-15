#![feature(array_zip, array_methods)]

mod constants;
mod u32ct;

use tfhe::boolean::{client_key::ClientKey, server_key::ServerKey};

type MessageCiphertext = ();
type HashCiphertext = ();

pub fn encrypt_message(_message: &[u8], _client_key: &ClientKey) -> MessageCiphertext {
    todo!()
}

pub fn sha256_tfhe(_message_ct: MessageCiphertext, _server_key: &ServerKey) -> HashCiphertext {
    todo!()
}

pub fn decrypt_hash(_hash_ct: HashCiphertext, _client_key: &ClientKey) -> [u8; 32] {
    todo!()
}
