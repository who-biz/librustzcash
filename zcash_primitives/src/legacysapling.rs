use sapling::pedersen_hash::pedersen_hash;
use sapling::pedersen_hash::Personalization;
use sapling::Note;
use incrementalmerkletree;
use bitvec::{order::Lsb0, view::AsBits};
use lazy_static::lazy_static;
use rand_core::{CryptoRng, RngCore};
use std::io::{self, Read, Write};
use group::Curve;
use ff::PrimeField;

use crate::merkle_tree::Hashable;

const MODULUS_BITS: u32 = 252;
const NUM_BITS: u32 = MODULUS_BITS;

pub const SAPLING_COMMITMENT_TREE_DEPTH: usize = 32;

lazy_static! {
    static ref EMPTY_ROOTS: Vec<Node> = {
        let mut v = vec![Node::blank()];
        for d in 0..SAPLING_COMMITMENT_TREE_DEPTH {
            let next = Node::combine(d, &v[d], &v[d]);
            v.push(next);
        }
        v
    };
}

/// Compute a parent node in the Sapling commitment tree given its two children.
pub fn merkle_hash(depth: usize, lhs: &[u8; 32], rhs: &[u8; 32]) -> [u8; 32] {
    let lhs = {
        let mut tmp = [false; 256];
        for (a, b) in tmp.iter_mut().zip(lhs.as_bits::<Lsb0>()) {
            *a = *b;
        }
        tmp
    };

    let rhs = {
        let mut tmp = [false; 256];
        for (a, b) in tmp.iter_mut().zip(rhs.as_bits::<Lsb0>()) {
            *a = *b;
        }
        tmp
    };

    jubjub::ExtendedPoint::from(pedersen_hash(
        Personalization::MerkleTree(depth),
        lhs.iter()
            .copied()
            .take(NUM_BITS as usize)
            .chain(
                rhs.iter()
                    .copied()
                    .take(NUM_BITS as usize),
            ),
    ))
    .to_affine()
    .get_u()
    .to_repr()
}

/// A node within the Sapling commitment tree.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Node {
    repr: [u8; 32],
}

impl Node {
    pub fn new(repr: [u8; 32]) -> Self {
        Node { repr }
    }
}

impl Hashable for Node {
    fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut repr = [0u8; 32];
        reader.read_exact(&mut repr)?;
        Ok(Node::new(repr))
    }

    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(self.repr.as_ref())
    }

    fn combine(depth: usize, lhs: &Self, rhs: &Self) -> Self {
        Node {
            repr: merkle_hash(depth, &lhs.repr, &rhs.repr),
        }
    }

        fn blank() -> Self {
            Node::new([0u8; 32])
        }

    fn empty_root(depth: usize) -> Self {
        EMPTY_ROOTS[depth]
    }
}
