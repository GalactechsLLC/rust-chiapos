use std::error::Error;
use std::ops::Range;

pub struct ChachaContext {
    pub input: [u32; 16],
}

const fn rol32(a: u32, n: u32) -> u32 {
    ((a) << (n)) | ((a) >> (32 - (n)))
}

const fn chacha_quarter_round(mut a: u32, mut b: u32, mut c: u32, mut d: u32) {
    a += b;
    d ^= a;
    d = rol32(d, 16);
    c += d;
    b ^= c;
    b = rol32(b, 12);
    a += b;
    d ^= a;
    d = rol32(d, 8);
    c += d;
    b ^= c;
    b = rol32(b, 7);
    let _ = b;
}

pub fn chacha8_keysetup(
    context: &mut ChachaContext,
    key: &[u8; 32],
    nonce: Option<&[u8; 8]>,
) -> Result<(), Box<dyn Error>> {
    context.input[0] = 0x61707865;
    context.input[1] = 0x3320646E;
    context.input[2] = 0x79622D32;
    context.input[3] = 0x6B206574;
    //Input words 4 through 11 are taken from the 256-bit key, by reading
    //the bytes in little-endian order, in 4-byte chunks
    context.input[4] = u32::from_le_bytes(key[0..4].try_into()?);
    context.input[5] = u32::from_le_bytes(key[4..8].try_into()?);
    context.input[6] = u32::from_le_bytes(key[8..12].try_into()?);
    context.input[7] = u32::from_le_bytes(key[12..16].try_into()?);
    context.input[8] = u32::from_le_bytes(key[16..20].try_into()?);
    context.input[9] = u32::from_le_bytes(key[20..24].try_into()?);
    context.input[10] = u32::from_le_bytes(key[24..28].try_into()?);
    context.input[11] = u32::from_le_bytes(key[28..32].try_into()?);
    if nonce.is_some() {
        let nonce = nonce.unwrap();
        //Input words 12 and 13 are a block counter, with word 12
        //overflowing into word 13
        context.input[12] = 0;
        context.input[13] = 0;

        //Input words 14 and 15 are taken from an 64-bit nonce, by reading
        //the bytes in little-endian order, in 4-byte chunks
        context.input[14] = u32::from_le_bytes(nonce[0..4].try_into()?);
        context.input[15] = u32::from_le_bytes(nonce[4..8].try_into()?);
    } else {
        context.input[14] = 0;
        context.input[15] = 0;
    }
    Ok(())
}

pub fn chacha8_get_keystream(
    context: &ChachaContext,
    pos: u64,
    mut n_blocks: u32,
    cypher_text: &mut Vec<u8>,
) {
    let mut x0: u32;
    let mut x1: u32;
    let mut x2: u32;
    let mut x3: u32;
    let mut x4: u32;
    let mut x5: u32;
    let mut x6: u32;
    let mut x7: u32;
    let mut x8: u32;
    let mut x9: u32;
    let mut x10: u32;
    let mut x11: u32;
    let mut x12: u32;
    let mut x13: u32;
    let mut x14: u32;
    let mut x15;
    let mut i;
    let mut c = 0;

    let j0: u32 = context.input[0];
    let j1: u32 = context.input[1];
    let j2: u32 = context.input[2];
    let j3: u32 = context.input[3];
    let j4: u32 = context.input[4];
    let j5: u32 = context.input[5];
    let j6: u32 = context.input[6];
    let j7: u32 = context.input[7];
    let j8: u32 = context.input[8];
    let j9: u32 = context.input[9];
    let j10: u32 = context.input[10];
    let j11: u32 = context.input[11];
    let mut j12: u32 = pos.to_le() as u32;
    let mut j13: u32 = (pos.to_le() >> 32) as u32;
    let j14: u32 = context.input[14];
    let j15: u32 = context.input[15];

    while n_blocks > 0 {
        x0 = j0;
        x1 = j1;
        x2 = j2;
        x3 = j3;
        x4 = j4;
        x5 = j5;
        x6 = j6;
        x7 = j7;
        x8 = j8;
        x9 = j9;
        x10 = j10;
        x11 = j11;
        x12 = j12;
        x13 = j13;
        x14 = j14;
        x15 = j15;
        i = 8;
        while i > 0 {
            chacha_quarter_round(x0, x4, x8, x12);
            chacha_quarter_round(x1, x5, x9, x13);
            chacha_quarter_round(x2, x6, x10, x14);
            chacha_quarter_round(x3, x7, x11, x15);
            chacha_quarter_round(x0, x5, x10, x15);
            chacha_quarter_round(x1, x6, x11, x12);
            chacha_quarter_round(x2, x7, x8, x13);
            chacha_quarter_round(x3, x4, x9, x14);
            i -= 2;
        }
        x0 += j0;
        x1 += j1;
        x2 += j2;
        x3 += j3;
        x4 += j4;
        x5 += j5;
        x6 += j6;
        x7 += j7;
        x8 += j8;
        x9 += j9;
        x10 += j10;
        x11 += j11;
        x12 += j12;
        x13 += j13;
        x14 += j14;
        x15 += j15;
        j12 = j12.wrapping_add(1);
        if j12 == 0 {
            j13 += 1;
        }
        cypher_text.splice(Range::from(c + 0..c + 4), x0.to_le_bytes());
        cypher_text.splice(Range::from(c + 4..c + 8), x1.to_le_bytes());
        cypher_text.splice(Range::from(c + 8..c + 12), x2.to_le_bytes());
        cypher_text.splice(Range::from(c + 12..c + 16), x3.to_le_bytes());
        cypher_text.splice(Range::from(c + 16..c + 20), x4.to_le_bytes());
        cypher_text.splice(Range::from(c + 20..c + 24), x5.to_le_bytes());
        cypher_text.splice(Range::from(c + 24..c + 28), x6.to_le_bytes());
        cypher_text.splice(Range::from(c + 28..c + 32), x7.to_le_bytes());
        cypher_text.splice(Range::from(c + 32..c + 36), x8.to_le_bytes());
        cypher_text.splice(Range::from(c + 36..c + 40), x9.to_le_bytes());
        cypher_text.splice(Range::from(c + 40..c + 44), x10.to_le_bytes());
        cypher_text.splice(Range::from(c + 44..c + 48), x11.to_le_bytes());
        cypher_text.splice(Range::from(c + 48..c + 52), x12.to_le_bytes());
        cypher_text.splice(Range::from(c + 52..c + 56), x13.to_le_bytes());
        cypher_text.splice(Range::from(c + 56..c + 60), x14.to_le_bytes());
        cypher_text.splice(Range::from(c + 60..c + 64), x15.to_le_bytes());
        c += 64;
        n_blocks -= 1;
    }
}
