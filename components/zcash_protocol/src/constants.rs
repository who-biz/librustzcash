//! Network-specific Zcash constants.

pub mod zec;
pub mod vrsc;

/// Different networks used for differentiating between sapling activation heights, constants, etc. and their IDs
#[derive(Copy, Clone)]
pub enum ChainNetwork {
    VRSC,
    ZEC
}
