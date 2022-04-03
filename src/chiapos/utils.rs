use bit_vec::BitVec;
use std::error::Error;

pub fn bit_vec_slice(vector: &BitVec, start: usize, end: usize) -> BitVec {
    let mut end = end;
    if end > vector.len() {
        end = vector.len();
    }
    if end <= start {
        return BitVec::new();
    }
    let mut slice = BitVec::with_capacity(end - start);
    let mut index = start;
    while index < end {
        slice.set(index, vector[index]);
        index += 1;
    }
    slice
}

pub fn bit_vec_slice_to_int(
    vector: &BitVec,
    start: usize,
    end: usize,
) -> Result<u64, Box<dyn Error>> {
    let mut end = end;
    if end > vector.len() {
        end = vector.len();
    }
    if end <= start {
        return Ok(0);
    }
    let mut slice = BitVec::with_capacity(end - start);
    let mut index = start;
    while index < end {
        slice.set(index, vector[index]);
        index += 1;
    }
    Ok(u64::from_be_bytes(slice.to_bytes().as_slice().try_into()?))
}

pub fn byte_align(num_bits: u32) -> u32 {
    num_bits + (8 - ((num_bits) % 8)) % 8
}
