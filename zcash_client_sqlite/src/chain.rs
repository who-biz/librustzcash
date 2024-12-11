//! Functions for enforcing chain validity and handling chain reorgs.
//!
//! # Examples
//!
//! ```
//! use rusqlite::Connection;
//! use zcash_primitives::{
//!     consensus::{BlockHeight, Network, Parameters}
//! };
//!
//! use zcash_client_sqlite::{
//!     chain::{rewind_to_height, validate_combined_chain},
//!     error::ErrorKind,
//!     scan::scan_cached_blocks,
//! };
//!
//! let network = Network::TestNetwork;
//! let db_cache = "/path/to/cache.db";
//! let db_data = "/path/to/data.db";
//!
//! // 1) Download new CompactBlocks into db_cache.
//!
//! // 2) Run the chain validator on the received blocks.
//! //
//! // Given that we assume the server always gives us correct-at-the-time blocks, any
//! // errors are in the blocks we have previously cached or scanned.
//! if let Err(e) = validate_combined_chain(network, &db_cache, &db_data) {
//!     match e.kind() {
//!         ErrorKind::InvalidChain(upper_bound, _) => {
//!             // a) Pick a height to rewind to.
//!             //
//!             // This might be informed by some external chain reorg information, or
//!             // heuristics such as the platform, available bandwidth, size of recent
//!             // CompactBlocks, etc.
//!             let rewind_height = *upper_bound - 10;
//!
//!             // b) Rewind scanned block information.
//!             rewind_to_height(network, &db_data, rewind_height);
//!
//!             // c) Delete cached blocks from rewind_height onwards.
//!             //
//!             // This does imply that assumed-valid blocks will be re-downloaded, but it
//!             // is also possible that in the intervening time, a chain reorg has
//!             // occurred that orphaned some of those blocks.
//!
//!             // d) If there is some separate thread or service downloading
//!             // CompactBlocks, tell it to go back and download from rewind_height
//!             // onwards.
//!         }
//!         _ => {
//!             // Handle other errors.
//!         }
//!     }
//! }
//!
//! // 3) Scan (any remaining) cached blocks.
//! //
//! // At this point, the cache and scanned data are locally consistent (though not
//! // necessarily consistent with the latest chain tip - this would be discovered the
//! // next time this codepath is executed after new blocks are received).
//! scan_cached_blocks(&network, &db_cache, &db_data, None);
//! ```

use rusqlite::{Connection, NO_PARAMS};
use std::path::Path;

use zcash_primitives::{
    consensus::{self, BlockHeight, NetworkUpgrade},
    constants::{ChainNetwork}
};

use zcash_client_backend::proto::compact_formats::CompactBlock;

use std::io::{Error, ErrorKind};
use prost::Message;
//use crate::error::{Error, ErrorKind};

#[derive(Debug)]
pub enum ChainInvalidCause {
    PrevHashMismatch,
    /// (expected_height, actual_height)
    HeightMismatch(BlockHeight, BlockHeight),
}

struct CompactBlockRow {
    height: BlockHeight,
    data: Vec<u8>,
}

