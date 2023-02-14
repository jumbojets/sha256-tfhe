mod constants;
mod u32ct;

use tfhe::shortint::{ClientKey, ServerKey};

type MessageCiphertext = ();
type HashCiphertext = ();


pub fn encrypt_message(message: &[u8], client_key: &ClientKey) -> MessageCiphertext {
    todo!()
}

pub fn sha256_tfhe(message_ct: MessageCiphertext, server_key: &ServerKey) -> HashCiphertext {
    todo!()
}

pub fn decrypt_hash(hash_ct: HashCiphertext, client_key: &ClientKey) -> [u8; 32] {
    todo!()
}
