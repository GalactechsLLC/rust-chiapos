use crate::chiapos::f_calc::F1Calculator;
use crate::chiapos::f_calc::FXCalculator;
use crate::chiapos::f_calc::K_BC;
use crate::chiapos::utils::bit_vec_slice;
use crate::chiapos::utils::bit_vec_slice_to_int;
use bit_vec::BitVec;
use sha2::{Digest, Sha256};
use std::error::Error;

pub fn get_quality_string(
    k: u8,
    proof: &Vec<u8>,
    quality_index: u16,
    challenge: &Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut proof = BitVec::from_bytes(proof.as_slice());
    let mut table_index = 0;
    while table_index < 7 {
        // = 1; table_index < 7; table_index++) {
        let mut new_proof: BitVec = Default::default();
        let size = k * (1 << (table_index - 1));
        let mut j = 0;
        while j < (1 << (7 - table_index)) {
            let mut left = bit_vec_slice(&proof, (j * size) as usize, ((j + 1) * size) as usize);
            let mut right =
                bit_vec_slice(&proof, ((j + 1) * size) as usize, ((j + 2) * size) as usize);
            if compare_proof_bits(&left, &right, k)? {
                left.append(&mut right);
                new_proof.append(&mut left);
            } else {
                right.append(&mut left);
                new_proof.append(&mut right);
            }
            j += 2;
        }
        proof = new_proof;
        table_index += 1;
    }
    // Hashes two of the x values, based on the quality index
    let mut to_hash = challenge.clone();
    to_hash.extend(
        bit_vec_slice(
            &proof,
            (k as u16 * quality_index) as usize,
            (k as u16 * (quality_index + 2)) as usize,
        )
        .to_bytes(),
    );
    let mut hasher: Sha256 = Sha256::new();
    hasher.update(to_hash);
    Ok(hasher.finalize().to_vec())
}

pub struct PlotEntry {
    pub y: u64,
    pub pos: u64,
    pub offset: u64,
    pub left_metadata: u128, // We only use left_metadata, unless metadata does not
    pub right_metadata: u128, // fit in 128 bits.
}

pub fn validate_proof(
    id: &[u8; 32],
    k: u8,
    challenge: &Vec<u8>,
    proof_bytes: &Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let proof_bits = BitVec::from_bytes(proof_bytes);
    if (k * 64) as usize != proof_bits.len() {
        return Ok(Vec::new());
    }
    let mut proof: Vec<BitVec> = Default::default();
    let mut ys: Vec<BitVec> = Default::default();
    let mut metadata: Vec<BitVec> = Default::default();
    let f1 = F1Calculator::new(k, id)?;

    let mut index: usize = 0;
    while index < 64 {
        let as_int =
            bit_vec_slice_to_int(&proof_bits, k as usize * index, k as usize * (index + 1))?;
        proof.push(BitVec::from_bytes(&as_int.to_be_bytes().to_vec()));
        index += 1;
    }

    // Calculates f1 for each of the given xs. Note that the proof is in proof order.
    index = 0;
    while index < 64 {
        let results = f1.calculate_bucket(&proof[index])?;
        ys.push(results.0);
        metadata.push(results.1);
    }

    // Calculates fx for each table from 2..7, making sure everything matches on the way.
    let mut depth = 2;
    while depth < 8 {
        let mut f = FXCalculator::new(k, depth);
        let mut new_ys: Vec<BitVec> = Default::default();
        let mut new_metadata: Vec<BitVec> = Default::default();
        index = 0;
        while index < (1 << (8 - depth)) {
            let mut l_plot_entry = PlotEntry {
                y: 0,
                pos: 0,
                offset: 0,
                left_metadata: 0,
                right_metadata: 0,
            };
            let mut r_plot_entry = PlotEntry {
                y: 0,
                pos: 0,
                offset: 0,
                left_metadata: 0,
                right_metadata: 0,
            };
            l_plot_entry.y = u64::from_be_bytes(ys[index].to_bytes().as_slice().try_into()?);
            r_plot_entry.y = u64::from_be_bytes(ys[index + 1].to_bytes().as_slice().try_into()?);
            let bucket_l: Vec<&PlotEntry> = vec![&l_plot_entry];
            let bucket_r: Vec<&PlotEntry> = vec![&r_plot_entry];

            // If there is no match, fails.
            let cdiff = r_plot_entry.y / K_BC as u64 - l_plot_entry.y / K_BC as u64;
            if cdiff != 1 {
                return Ok(Vec::new());
            } else {
                if f.find_matches(bucket_l, bucket_r, None, None) != 1 {
                    return Ok(Vec::new());
                }
            }
            let results = f.calculate_bucket(&ys[index], &metadata[index], &metadata[index + 1])?;
            new_ys.push(results.0);
            new_metadata.push(results.1);
            index += 2;
        }

        for new_y in &new_ys {
            if new_y.len() <= 0 {
                return Ok(Vec::new());
            }
        }
        ys = new_ys;
        metadata = new_metadata;
        depth += 1;
    }

    let challenge_bits = BitVec::from_bytes(challenge.as_slice());
    let quality_index = (u64::from_be_bytes(
        bit_vec_slice(&challenge_bits, 256 - 5, challenge_bits.len())
            .to_bytes()
            .as_slice()
            .try_into()?,
    ) << 1) as u16;

    // Makes sure the output is equal to the first k bits of the challenge
    if bit_vec_slice(&challenge_bits, 0, k as usize) == bit_vec_slice(&ys[0], 0, k as usize) {
        // Returns quality string, which requires changing proof to plot ordering
        return Ok(get_quality_string(
            k,
            &proof_bits.to_bytes(),
            quality_index,
            &challenge,
        )?);
    } else {
        return Ok(Vec::new());
    }
}

fn compare_proof_bits(left: &BitVec, right: &BitVec, k: u8) -> Result<bool, Box<dyn Error>> {
    let size = left.len() / k as usize;
    if left.len() != right.len() {
        return Err("Right and Left are not Equal".into());
    }
    let mut i = size - 1;
    while i > 0 {
        let left_val = bit_vec_slice(left, k as usize * i, k as usize * (i + 1));
        let right_val = bit_vec_slice(right, k as usize * i, k as usize * (i + 1));
        if left_val < right_val {
            return Ok(true);
        }
        if left_val > right_val {
            return Ok(false);
        }

        if i == 0 {
            break;
        }
        i -= 1;
    }
    return Ok(false);
}
