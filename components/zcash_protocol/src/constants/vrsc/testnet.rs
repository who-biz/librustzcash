//! Constants for the Zcash test network.

/// The testnet coin type for ZEC, as defined by [SLIP 44].
///
/// [SLIP 44]: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
pub const COIN_TYPE: u32 = 1;

/// The HRP for a Bech32-encoded testnet [`ExtendedSpendingKey`].
///
/// Defined in [ZIP 32].
///
/// [`ExtendedSpendingKey`]: zcash_primitives::zip32::ExtendedSpendingKey
/// [ZIP 32]: https://github.com/zcash/zips/blob/master/zip-0032.rst
pub const HRP_SAPLING_EXTENDED_SPENDING_KEY: &str = "secret-extended-key-test";

/// The HRP for a Bech32-encoded testnet [`ExtendedFullViewingKey`].
///
/// Defined in [ZIP 32].
///
/// [`ExtendedFullViewingKey`]: zcash_primitives::zip32::ExtendedFullViewingKey
/// [ZIP 32]: https://github.com/zcash/zips/blob/master/zip-0032.rst
pub const HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY: &str = "zxviewtestsapling";

/// The HRP for a Bech32-encoded testnet [`PaymentAddress`].
///
/// Defined in section 5.6.4 of the [Zcash Protocol Specification].
///
/// [`PaymentAddress`]: zcash_primitives::primitives::PaymentAddress
/// [Zcash Protocol Specification]: https://github.com/zcash/zips/blob/master/protocol/protocol.pdf
pub const HRP_SAPLING_PAYMENT_ADDRESS: &str = "ztestsapling";

/// The prefix for a Base58Check-encoded testnet [`TransparentAddress::PublicKey`].
///
/// [`TransparentAddress::PublicKey`]: zcash_primitives::legacy::TransparentAddress::PublicKey
pub const B58_PUBKEY_ADDRESS_PREFIX: [u8; 1] = [0x3c];

/// The prefix for a Base58Check-encoded testnet [`TransparentAddress::Script`].
///
/// [`TransparentAddress::Script`]: zcash_primitives::legacy::TransparentAddress::Script
pub const B58_SCRIPT_ADDRESS_PREFIX: [u8; 1] = [0x55];

/// The prefix for a Base58Check-encoded testnet Sprout address.
///
/// Defined in the [Zcash Protocol Specification section 5.6.3][sproutpaymentaddrencoding].
///
/// [sproutpaymentaddrencoding]: https://zips.z.cash/protocol/protocol.pdf#sproutpaymentaddrencoding
pub const B58_SPROUT_ADDRESS_PREFIX: [u8; 1] = [0xb6];

/// The HRP for a Bech32m-encoded testnet [ZIP 320] TEX address.
///
/// [ZIP 320]: https://zips.z.cash/zip-0320
pub const HRP_TEX_ADDRESS: &str = "textest";
