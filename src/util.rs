use tfhe::boolean::server_key::ServerKey;

use crate::u32ct::U32Ct;

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
