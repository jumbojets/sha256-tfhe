# a fully homomorphic sha256 circuit using tfhe-rs

### usage

```rust
use sha256_tfhe::{decrypt_digest, encrypt_input, sha256_tfhe};
let (client_key, server_key) = tfhe::boolean::gen_keys();
let input = b"hello world".to_vec();
let input_ct = encrypt_input(input, &client_key);
let digest_ct = sha256_tfhe(&input_ct, &server_key);
let digest = decrypt_digest(&digest_ct, &client_key);
println!("H(x) = {digest:?}");
```
