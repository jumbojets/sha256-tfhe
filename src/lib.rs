#![feature(array_methods, array_zip, iter_array_chunks)]

mod constants;
mod u32ct;
mod util;

use serde::{Deserialize, Serialize};
use tfhe::boolean::{client_key::ClientKey, server_key::ServerKey};

use u32ct::U32Ct;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MessageCt {
    inner: Vec<U32Ct>,
}

pub struct HashCt {
    inner: [U32Ct; 8],
}

pub fn encrypt_message(mut message: Vec<u8>, client_key: &ClientKey) -> MessageCt {
    // padding
    let length = message.len() as u64;
    message.push(0x80);
    while message.len() * 8 + 64 != 0 {
        message.push(0x00);
    }
    let len_be_bytes = length.to_be_bytes();
    message.extend(&len_be_bytes);
    assert!(message.len() % 512 == 0);    
    // encrypt using the client key
    let inner = message
        .into_iter()
        .array_chunks::<4>()
        .map(u32::from_be_bytes)
        .map(|x| U32Ct::encrypt(x, client_key))
        .collect::<Vec<_>>();
    MessageCt { inner }
}

pub fn sha256_tfhe(_message_ct: &MessageCt, _server_key: &ServerKey) -> HashCt {
    todo!()
}

pub fn decrypt_hash(_hash_ct: &HashCt, _client_key: &ClientKey) -> [u8; 32] {
    todo!()
}
