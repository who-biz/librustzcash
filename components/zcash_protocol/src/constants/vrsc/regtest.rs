//! # Regtest constants
//!
//! `regtest` is a `zcashd`-specific environment used for local testing. They mostly reuse
//! the testnet constants.
//! These constants are defined in [the `zcashd` codebase].
//! [the `zcashd` codebase]: https://github.com/zcash/zcash/blob/128d863fb8be39ee294fda397c1ce3ba3b889cb2/src/chainparams.cpp#L482-L496

/// The regtest cointype reuses the testnet cointype
pub const COIN_TYPE: u32 = 1;

/// The HRP for a Bech32-encoded regtest [`ExtendedSpendingKey`].
///
/// It is defined in [the `zcashd` codebase].
///
/// [`ExtendedSpendingKey`]: zcash_primitives::zip32::ExtendedSpendingKey
/// [the `zcashd` codebase]: https://github.com/zcash/zcash/blob/128d863fb8be39ee294fda397c1ce3ba3b889cb2/src/chainparams.cpp#L496
pub const HRP_SAPLING_EXTENDED_SPENDING_KEY: &str = "secret-extended-key-regtest";

/// The HRP for a Bech32-encoded regtest [`ExtendedFullViewingKey`].
///
/// It is defined in [the `zcashd` codebase].
///
/// [`ExtendedFullViewingKey`]: zcash_primitives::zip32::ExtendedFullViewingKey
/// [the `zcashd` codebase]: https://github.com/zcash/zcash/blob/128d863fb8be39ee294fda397c1ce3ba3b889cb2/src/chainparams.cpp#L494
pub const HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY: &str = "zxviewregtestsapling";

/// The HRP for a Bech32-encoded regtest [`PaymentAddress`].
///
/// It is defined in [the `zcashd` codebase].
///
/// [`PaymentAddress`]: zcash_primitives::primitives::PaymentAddress
/// [the `zcashd` codebase]: https://github.com/zcash/zcash/blob/128d863fb8be39ee294fda397c1ce3ba3b889cb2/src/chainparams.cpp#L493
pub const HRP_SAPLING_PAYMENT_ADDRESS: &str = "zregtestsapling";

/// The prefix for a Base58Check-encoded regtest [`TransparentAddress::PublicKey`].
/// Same as the testnet prefix.
///
/// [`TransparentAddress::PublicKey`]: zcash_primitives::legacy::TransparentAddress::PublicKey
pub const B58_PUBKEY_ADDRESS_PREFIX: [u8; 1] = [0x3c];

/// The prefix for a Base58Check-encoded regtest [`TransparentAddress::Script`].
/// Same as the testnet prefix.
///
/// [`TransparentAddress::Script`]: zcash_primitives::legacy::TransparentAddress::Script
pub const B58_SCRIPT_ADDRESS_PREFIX: [u8; 1] = [0x55];

/// The prefix for a Base58Check-encoded regtest Sprout address.
///
/// Defined in the [Zcash Protocol Specification section 5.6.3][sproutpaymentaddrencoding].
/// Same as the testnet prefix.
///
/// [sproutpaymentaddrencoding]: https://zips.z.cash/protocol/protocol.pdf#sproutpaymentaddrencoding
pub const B58_SPROUT_ADDRESS_PREFIX: [u8; 1] = [0xb6];

/// The HRP for a Bech32m-encoded regtest [ZIP 320] TEX address.
///
/// [ZIP 320]: https://zips.z.cash/zip-0320
pub const HRP_TEX_ADDRESS: &str = "texregtest";
