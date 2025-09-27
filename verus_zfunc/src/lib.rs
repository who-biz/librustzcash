use anyhow::{anyhow, Result};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
use hex;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use ripemd::Ripemd160;

use sapling::{
    keys::SaplingIvk,
    note_encryption::{PreparedIncomingViewingKey, SaplingDomain},
    value::NoteValue,
    zip32::{DiversifiableFullViewingKey, ExtendedSpendingKey},
    Note, Rseed,
};
use zcash_keys::address::Address;
use zcash_note_encryption::{Domain, EphemeralKeyBytes};
use zcash_primitives::{
    consensus::Network,
    zip32::{ChildIndex, Scope},
};
use blake2b_simd::{Hash as Blake2bHash};

struct DummyRng;
impl RngCore for DummyRng {
    fn next_u32(&mut self) -> u32 { 0 }
    fn next_u64(&mut self) -> u64 { 0 }
    fn fill_bytes(&mut self, dest: &mut [u8]) { dest.fill(0); }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
        dest.fill(0);
        Ok(())
    }
}
impl CryptoRng for DummyRng {}


pub struct RpcParams {
    pub seed: Option<String>,
    pub spending_key: Option<String>,
    pub hd_index: u32,
    pub encryption_index: u32,
    pub from_id: Option<String>,
    pub to_id: Option<String>,
    pub return_secret: bool,
}

pub struct ChannelKeys {
    pub address: String,
    pub fvk: String,
    pub spending_key: Option<String>,
    pub ivk: Option<String>
}

pub struct EncryptedPayload {
    pub ephemeral_public_key: String,
    pub ciphertext: String,
    pub symmetric_key: Option<String>,
}

pub struct DecryptParams {
    pub fvk_hex: Option<String>,
    pub ephemeral_public_key_hex: Option<String>,
    pub ciphertext_hex: String,
    pub symmetric_key_hex: Option<String>,
}

// derives a shared symmetric key using the receiver's private viewing key
// and the sender's public key

fn internal_get_symmetric_key_receiver(
    dfvk_bytes: &[u8],
    ephemeral_pk_bytes: &[u8],
) -> Result<Blake2bHash> {

    // parse the viewing key bytes into a key object
    let dfvk_bytes_array: [u8; 128] = dfvk_bytes
      .try_into()
      .map_err(|_| anyhow!("DFVK data must be 128 bytes long."))?;
    let dfvk = DiversifiableFullViewingKey::from_bytes(&dfvk_bytes_array)
      .ok_or_else(|| anyhow!("Failed to parse DFVK from bytes"))?;

   // extract the incoming viewing key (ivk), the private part needed for decryption
    let ivk: SaplingIvk = dfvk.to_ivk(Scope::External);
    let sapling_ivk = PreparedIncomingViewingKey::new(&ivk);

    // parse the sender's public key bytes into a key object
    let epk_array: [u8; 32] = ephemeral_pk_bytes
      .try_into()
      .map_err(|_| anyhow!("EPK must be 32 bytes"))?;
    let epk_bytes = EphemeralKeyBytes(epk_array);
    let epk = <SaplingDomain as Domain>::epk(&epk_bytes)
      .ok_or_else(|| anyhow!("Failed to create EphemeralPublicKey"))?;

    // prepare the public key
    let prepared_epk = <SaplingDomain as Domain>::prepare_epk(epk);

    // perform key agreement (ecdh) to calculate the shared secret
    let shared_secret = <SaplingDomain as Domain>::ka_agree_dec(&sapling_ivk, &prepared_epk);

    // derive the final symmetric key using the key derivation function/kdf
    Ok(<SaplingDomain as Domain>::kdf(shared_secret, &epk_bytes))
}


// this internal function generates a symmetric key from the sender's side
// it creates a temporary, single-use key pair and uses the recipient's public
// address to establish a shared secret

fn internal_generate_symmetric_key_sender(
    address: &Address,
    rseed_bytes: &[u8],
) -> Result<(Blake2bHash, EphemeralKeyBytes)> {

    //ensures the provided address is a sapling address
    let recipient = match address {
        Address::Sapling(addr) => addr,
        _ => return Err(anyhow!("Incompatible Address used")),
    };

     // seed is a required component for creating a note, from which the
    // temporary encryption keys are derived

    let rseed_array: [u8; 32] = rseed_bytes.try_into()?;
    let rseed = Rseed::AfterZip212(rseed_array);

        // create a dummy note, which is a necessary component for deriving the keys
    let note = Note::from_parts(recipient.clone(), NoteValue::from_raw(0), rseed);

    // create a dummy rng to satisfy the function signature. this is not used for randomness.
    let mut dummy_rng = DummyRng;

    // generates a new, single-use ephemeral secret key (esk) deterministically from the rseed.
    // this is the sender's temporary private key for this one-time encryption.
    let esk = note.generate_or_derive_esk(&mut dummy_rng);

    // derives the corresponding ephemeral public key (epk)
    let epk = <SaplingDomain as Domain>::ka_derive_public(&note, &esk);
    let epk_bytes = <SaplingDomain as Domain>::epk_bytes(&epk);

    //it combines the sender's esk with the
    //recipient's pk_d to compute a secret value
    let pk_d = recipient.pk_d();
    let shared_secret = <SaplingDomain as Domain>::ka_agree_enc(&esk, pk_d);

    // derives the symmetric key using the shared secret and the ephemeral public key bytes
    let symmetric_key: Blake2bHash = <SaplingDomain as Domain>::kdf(shared_secret, &epk_bytes);

    Ok((symmetric_key, epk_bytes))
}


// generates a standard BIP-44 derived spending key from a seed.
pub fn generate_spending_key(seed_hex: String, hd_index: u32) -> Result<String> {
    let seed_bytes = hex::decode(seed_hex)?;
    if seed_bytes.len() < 32 {
        return Err(anyhow!("Seed must be at least 32 bytes"));
    }

    // perform the BIP-44 derivation as your main function

    let master_sk = ExtendedSpendingKey::master(&seed_bytes);
    let purpose_key = master_sk.derive_child(ChildIndex::hardened(32));
    let coin_type_key = purpose_key.derive_child(ChildIndex::hardened(133));
    let account_sk = coin_type_key.derive_child(ChildIndex::hardened(hd_index));

    // serialize the derived key to bytes
    let mut sk_bytes = Vec::new();
    account_sk.write(&mut sk_bytes)?;

    // return the hex-encoded spending key
    Ok(hex::encode(sk_bytes))
}

// generates a unique, deterministic encryption address for a communication channel
// between two parties, identified by from_id` and `to_id
pub fn z_getencryptionaddress(params: RpcParams) -> Result<ChannelKeys> {
    // determine the base spending key from either a seed or a provided key
    let base_sk = if let Some(seed_hex) = params.seed {
        // if a seed is provided, derive the account key using the hd_index
        let seed_bytes = hex::decode(seed_hex)?;
        if seed_bytes.len() != 32 && seed_bytes.len() != 64 {
            return Err(anyhow!("Seed for encryption address must be 32 or 64 bytes (hex)"));
        }

        // derive base spending key using the daemon's fixed path m/32'/coin_type'/hd_index'
        let master_sk = ExtendedSpendingKey::master(&seed_bytes);
        let purpose_key = master_sk.derive_child(ChildIndex::hardened(32));
        // Use Verus/your code's coin type (133 used previously). If you have dynamic coin type, replace here.
        let coin_type_key = purpose_key.derive_child(ChildIndex::hardened(133));
        coin_type_key.derive_child(ChildIndex::hardened(params.hd_index))
    } else if let Some(sk_hex) = params.spending_key {
        // if a spending key is provided, decode and use it directly
        let sk_bytes = hex::decode(sk_hex)?;
        let sk_bytes_array: [u8; 169] = sk_bytes
            .try_into()
            .map_err(|_| anyhow!("Invalid spending key length"))?;
        ExtendedSpendingKey::from_bytes(&sk_bytes_array)
            .map_err(|_| anyhow!("Failed to parse spending key"))?
    } else {
        return Err(anyhow!("Must provide 'seed' or 'spendingKey'"));
    };

    // serialize base spending key
    let mut base_sk_bytes = Vec::new();
    base_sk.write(&mut base_sk_bytes)?;

    // concatenate bytes and then hash, exactly like the JNI function ---
    let mut encryption_seed_bytes = base_sk_bytes.clone();

    // helper to parse id param into 20-byte hash160 (either accept 40-hex hex or compute RIPEMD160(SHA256(text)))
    fn id_to_h160_bytes(id: &str) -> Result<[u8; 20]> {
        // fast path: if caller provided 40 hex chars, treat as the h160 directly
        if id.len() == 40 && id.chars().all(|c| c.is_ascii_hexdigit()) {
            let b = hex::decode(id)?;
            if b.len() != 20 {
                return Err(anyhow!("id hex must be 20 bytes"));
            }
            let arr: [u8; 20] = b.try_into().unwrap();
            return Ok(arr);
        }
        // otherwise compute hash160 = RIPEMD160(SHA256(id_bytes))
        let sha = Sha256::digest(id.as_bytes());
        let rip = Ripemd160::digest(&sha);
        let arr: [u8; 20] = rip.into();
        Ok(arr)
    }

    // if from_id present, append byte-flipped hash160
    if let Some(id_str) = params.from_id.as_ref() {
        if !id_str.is_empty() {
            let mut h160 = id_to_h160_bytes(id_str)?;
            h160.reverse(); // byte-flip to match daemon little-endian ordering
            encryption_seed_bytes.extend_from_slice(&h160);
        }
    else {
            encryption_seed_bytes.push(0u8);
        }
    } else {
        encryption_seed_bytes.push(0u8);
    }
    // if to_id present, append byte-flipped hash160
    if let Some(id_str) = params.to_id.as_ref() {
        if !id_str.is_empty() {
            let mut h160 = id_to_h160_bytes(id_str)?;
            h160.reverse(); // byte-flip to match daemon little-endian ordering
            encryption_seed_bytes.extend_from_slice(&h160);
        }
    }

    // here is our unique, deterministic seed for the communication channel
    let channel_seed: [u8; 32] = Sha256::digest(&encryption_seed_bytes).into();

    // use the new channel seed to derive the final key for this channel
    // using the `encryption_index` but preserving the daemon's path m/32'/coin_type'/encryption_index'
    let channel_master_sk = ExtendedSpendingKey::master(&channel_seed);
    let channel_purpose = channel_master_sk.derive_child(ChildIndex::hardened(32));
    let channel_coin = channel_purpose.derive_child(ChildIndex::hardened(133)); // use same coin type as above
    let final_sk = channel_coin.derive_child(ChildIndex::hardened(params.encryption_index));

    // get the view-only key (dfvk) from the final spending key
    let dfvk = final_sk.to_diversifiable_full_viewing_key();

    let network = Network::MainNetwork;
    let (_diversifier, payment_address) = dfvk.default_address();
    let addr = Address::from(payment_address);

    let ivk = dfvk.to_ivk(Scope::External);


    // prepare the final address and fvk in the channelkeys struct to be returned
    let channel_keys = ChannelKeys {
        address: addr.encode(&network),
        fvk: hex::encode(dfvk.to_bytes()),
        spending_key: if params.return_secret {
            let mut sk_bytes = Vec::new();
            final_sk.write(&mut sk_bytes)?;
            Some(hex::encode(sk_bytes))
        } else {
            None
        },
        ivk: Some(hex::encode(ivk.0.to_bytes())),
    };

    Ok(channel_keys)
}


// encrypts a message for a given zcash address
pub fn encrypt_message(
    address_string: String,
    message: String,
    return_ssk: bool,
) -> Result<EncryptedPayload> {
    let network = Network::MainNetwork;

    // decode the address string into a structured address object
    let addr = Address::decode(&network, &address_string)
     .ok_or_else(|| anyhow!("Address is for the wrong network or invalid"))?;

    // generate fresh random bytes for the note's rseed
    let mut rseed_bytes = [0u8; 32];
    getrandom::getrandom(&mut rseed_bytes)?;

    // call the internal helper to perform the key exchange
    // this returns the shared symmetric key and the public ephemeral key
    let (symmetric_key_hash, epk_bytes) =
        internal_generate_symmetric_key_sender(&addr, &rseed_bytes)?;

    // The key for the cipher is the first 32 bytes of the 64-byte hash
    let key_bytes: [u8; 32] = symmetric_key_hash.as_bytes()[..32].try_into()?;

    // initialize the chacha20poly1305 cipher with the 32-byte key
    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
      .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;
    let nonce = chacha20poly1305::Nonce::default();
    let mut buffer = message.into_bytes();

    // encrypt the message in place using the cipher and nonce
    cipher
     .encrypt_in_place(&nonce, b"", &mut buffer)
     .map_err(|_| anyhow!("Encryption failed"))?;

    // prepare the encrypted payload to be returned
    let result = EncryptedPayload {
        ephemeral_public_key: hex::encode(epk_bytes.0),
        ciphertext: hex::encode(buffer),
        symmetric_key: if return_ssk {
            // IMPORTANT: Return the 32-byte key that was actually used for encryption
            Some(hex::encode(key_bytes))
        } else {
            None
        },
    };

    Ok(result)
}

// decrypts a message using either a direct symmetric key, or by deriving
// the key from a full viewing key and the senders ephemeral public key
pub fn decrypt_message(params: DecryptParams) -> Result<String> {
    // This buffer will hold the final 32-byte key for the cipher
    let mut key_bytes = [0u8; 32];

    if let Some(ssk_hex) = params.symmetric_key_hex {
        // if a symmetric key is provided, decode it directly
        let ssk_bytes_vec = hex::decode(ssk_hex)?;
        // IMPORTANT: We now expect the 32-byte key
        let ssk_bytes: [u8; 32] = ssk_bytes_vec
            .try_into()
            .map_err(|_| anyhow!("Provided symmetric key must be 32 bytes"))?;
        key_bytes.copy_from_slice(&ssk_bytes);

    } else if let (Some(fvk_hex), Some(epk_hex)) = (params.fvk_hex, params.ephemeral_public_key_hex) {
        // derive the key using the FVK and sender's public key
        let fvk_bytes = hex::decode(fvk_hex)?;
        let epk_bytes = hex::decode(epk_hex)?;
        let symmetric_key_hash = internal_get_symmetric_key_receiver(&fvk_bytes, &epk_bytes)?;
        // Copy the first 32 bytes from the derived hash into our key buffer
        key_bytes.copy_from_slice(&symmetric_key_hash.as_bytes()[..32]);
    } else {
        return Err(anyhow!(
            "Must provide either a symmetricKeyHex or both fvkHex and ephemeralPublicKeyHex"
        ));
    };

    // decode the ciphertext hex into a mutable byte buffer for in-place decryption
    let mut buffer = hex::decode(params.ciphertext_hex)?;

    // initialize the chacha20poly1305 cipher with the 32-byte key
    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
     .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;
    let nonce = chacha20poly1305::Nonce::default();

     // decrypt the buffer in place. this will fail if the key is incorrect.
    cipher
   .decrypt_in_place(&nonce, b"", &mut buffer)
   .map_err(|_| anyhow!("Decryption failed. Key or ciphertext may be incorrect."))?;

     // convert the decrypted bytes back into a readable string
    String::from_utf8(buffer)
   .map_err(|_| anyhow!("Failed to parse decrypted message as a UTF-8 string.").into())
}
