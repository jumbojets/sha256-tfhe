use tfhe::boolean::server_key::ServerKey;

use crate::u32ct::U32Ct;

pub fn pad_message(mut msg: Vec<u8>) -> Vec<u8> {
    let length = (msg.len() * 8) as u64;
    msg.push(0x80);
    while (msg.len() * 8 + 64) % 512 != 0 {
        msg.push(0x00);
    }
    let len_be_bytes = length.to_be_bytes();
    msg.extend(&len_be_bytes);
    assert_eq!((msg.len() * 8) % 512, 0);
    msg
}

pub fn sigma0(x: &U32Ct, server_key: &ServerKey) -> U32Ct {
    let rotate_7 = x.rotate_right(7);
    let rotate_18 = x.rotate_right(18);
    let shift_3 = x.shift_right(3, server_key);
    let xor_7_18 = rotate_7.bitxor(&rotate_18, server_key);
    xor_7_18.bitxor(&shift_3, server_key)
}

pub fn sigma1(x: &U32Ct, server_key: &ServerKey) -> U32Ct {
    let rotate_17 = x.rotate_right(17);
    let rotate_19 = x.rotate_right(19);
    let shift_10 = x.shift_right(10, server_key);
    let xor_17_19 = rotate_17.bitxor(&rotate_19, server_key);
    xor_17_19.bitxor(&shift_10, server_key)
}

pub fn capsigma0(x: &U32Ct, server_key: &ServerKey) -> U32Ct {
    let rotate_2 = x.rotate_right(2);
    let rotate_13 = x.rotate_right(13);
    let rotate_22 = x.rotate_right(22);
    let xor_2_13 = rotate_2.bitxor(&rotate_13, server_key);
    xor_2_13.bitxor(&rotate_22, server_key)
}

pub fn capsigma1(x: &U32Ct, server_key: &ServerKey) -> U32Ct {
    let rotate_6 = x.rotate_right(6);
    let rotate_11 = x.rotate_right(11);
    let rotate_25 = x.rotate_right(25);
    let xor_6_11 = rotate_6.bitxor(&rotate_11, server_key);
    xor_6_11.bitxor(&rotate_25, server_key)
}

pub fn ch(x: &U32Ct, y: &U32Ct, z: &U32Ct, server_key: &ServerKey) -> U32Ct {
    let left = x.bitand(y, server_key);
    let not_x = x.bitnot(server_key);
    let right = not_x.bitand(z, server_key);
    left.bitxor(&right, server_key)
}

pub fn maj(x: &U32Ct, y: &U32Ct, z: &U32Ct, server_key: &ServerKey) -> U32Ct {
    let left = x.bitand(y, server_key);
    let middle = x.bitand(z, server_key);
    let right = y.bitand(z, server_key);
    let fold_l = left.bitxor(&middle, server_key);
    fold_l.bitxor(&right, server_key)
}

#[cfg(test)]
mod tests {
    use tfhe::boolean::gen_keys;

    use super::*;

    #[test]
    fn test_pad_message() {
        let msg = b"".to_vec();
        let padded = pad_message(msg);
        let mut expected = [0; 64];
        expected[0] = 0x80;
        assert_eq!(expected.to_vec(), padded);

        let msg = b"hello world".to_vec();
        let padded = pad_message(msg);
        let expected = [
            0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x80, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x58,
        ];
        assert_eq!(padded, expected);

        let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".to_vec();
        let padded = pad_message(msg);
        let expected = [
            97, 98, 99, 100, 101, 102, 103, 104, 98, 99, 100, 101, 102, 103, 104, 105, 99, 100,
            101, 102, 103, 104, 105, 106, 100, 101, 102, 103, 104, 105, 106, 107, 101, 102, 103,
            104, 105, 106, 107, 108, 102, 103, 104, 105, 106, 107, 108, 109, 103, 104, 105, 106,
            107, 108, 109, 110, 104, 105, 106, 107, 108, 109, 110, 111, 105, 106, 107, 108, 109,
            110, 111, 112, 106, 107, 108, 109, 110, 111, 112, 113, 107, 108, 109, 110, 111, 112,
            113, 114, 108, 109, 110, 111, 112, 113, 114, 115, 109, 110, 111, 112, 113, 114, 115,
            116, 110, 111, 112, 113, 114, 115, 116, 117, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 3, 128,
        ];
        assert_eq!(padded, expected);
    }

    type Scramble1 = fn(&U32Ct, &ServerKey) -> U32Ct;
    type Scramble3 = fn(&U32Ct, &U32Ct, &U32Ct, &ServerKey) -> U32Ct;

    fn test_scamble1(scramble: Scramble1, x: u32, y_expected: u32) {
        let (client_key, server_key) = gen_keys();
        let x = U32Ct::encrypt(x, &client_key);
        let y_ct = scramble(&x, &server_key);
        let y = y_ct.decrypt(&client_key);
        assert_eq!(y, y_expected);
    }

    fn test_scramble3(scramble: Scramble3, a: u32, b: u32, c: u32, y_expected: u32) {
        let (client_key, server_key) = gen_keys();
        let a = U32Ct::encrypt(a, &client_key);
        let b = U32Ct::encrypt(b, &client_key);
        let c = U32Ct::encrypt(c, &client_key);
        let y_ct = scramble(&a, &b, &c, &server_key);
        let y = y_ct.decrypt(&client_key);
        assert_eq!(y, y_expected);
    }

    #[test]
    fn test_sigma0() {
        test_scamble1(sigma0, 0b1111111111111111, 0b11000001111111111101111000000000);
    }

    #[test]
    fn test_sigma1() {
        test_scamble1(sigma1, 0b1111111111111111, 0b01100000000000000110000000111111);
    }

    #[test]
    fn test_capsigma0() {
        test_scamble1(capsigma0, 0b1111111111111111, 0b00111100000001111100001111111000);
    }

    #[test]
    fn test_capsigma1() {
        test_scamble1(capsigma1, 0b1111111111111111, 0b00000011100111111111110001100000);
    }

    #[test]
    fn test_ch() {
        test_scramble3(ch, 0xaaaa, 0xbbbb, 0xcccc, 61166);
    }

    #[test]
    fn test_maj() {
        test_scramble3(maj, 0xaaaa, 0xbbbb, 0xcccc, 43690);
    }
}
