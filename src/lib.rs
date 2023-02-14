mod constants;
mod u32;

use tfhe::shortint::{ClientKey, ServerKey};

type MessageCiphertext = ();

pub fn encrypt_message(msg: &[u8], client_key: &ClientKey) -> MessageCiphertext {
    todo!()
}

pub fn sha256_tfhe(message_ciphertext: MessageCiphertext, server_key: &ServerKey) -> [u8; 32] {
    todo!()
}
