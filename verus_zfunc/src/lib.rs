use anyhow::{anyhow, Result};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit};
use hex;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

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
    pub from_id: String,
    pub to_id: String,
    pub return_secret: bool,
}

pub struct ChannelKeys {
    pub address: String,
    pub fvk: String,
    pub spending_key: Option<String>,
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

// generates a unique, deterministic encryption address for a communication channel
// between two parties, identified by from_id` and `to_id
pub fn z_getencryptionaddress(params: RpcParams) -> Result<ChannelKeys> {

        // determine the base spending key from either a seed or a provided key
    let base_sk = if let Some(seed_hex) = params.seed {

                // if a seed is provided, derive the account key using the hd_index
        let seed_bytes = hex::decode(seed_hex)?;
        let master_sk = ExtendedSpendingKey::master(&seed_bytes);
        master_sk.derive_child(ChildIndex::hardened(params.hd_index))
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

    // decode id strings into bytes
    let from_id_bytes = hex::decode(params.from_id)?;
    let to_id_bytes = hex::decode(params.to_id)?;

    // hash the derived base key with the fromid and toid using sha256
    let mut hasher = Sha256::default();
    let mut base_sk_bytes = Vec::new();
    base_sk.write(&mut base_sk_bytes)?;
    hasher.update(&base_sk_bytes);
    hasher.update(from_id_bytes);
    hasher.update(to_id_bytes);

    // here is our unique, deterministic seed for the communication channel;
    let channel_seed: [u8; 32] = hasher.finalize().into();

    // use the new channel seed to derive the final key for this channel
    // using the `encryption_index`
    let channel_master_sk = ExtendedSpendingKey::master(&channel_seed);
    let final_sk = channel_master_sk.derive_child(ChildIndex::hardened(params.encryption_index));

    // get the view-only key (dfvk) from the final spending key
    let dfvk = final_sk.to_diversifiable_full_viewing_key();

    let network = Network::MainNetwork;
    let (_diversifier, payment_address) = dfvk.default_address();
    let addr = Address::from(payment_address);

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
    };


    Ok(channel_keys)
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

#[cfg(test)]
mod tests {
    use super::*;

    // Use a fixed, known seed for deterministic and repeatable test results.
    const TEST_SEED_HEX: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    const FROM_ID_HEX: &str = "73656e64657240"; 
    const TO_ID_HEX: &str = "726563697069656e7440"; 

    /// helper function to generate a standard set of channel keys for use in other tests
    fn setup_channel_keys() -> ChannelKeys {
        let params = RpcParams {
            seed: Some(TEST_SEED_HEX.to_string()),
            spending_key: None,
            hd_index: 0,
            encryption_index: 0,
            from_id: FROM_ID_HEX.to_string(),
            to_id: TO_ID_HEX.to_string(),
            return_secret: true, // Return the spending key for other tests
        };
        z_getencryptionaddress(params).expect("Failed to generate channel keys for setup")
    }


    #[test]
    fn test_generate_spending_key_success() {
        let result = generate_spending_key(TEST_SEED_HEX.to_string(), 0);
        assert!(result.is_ok(), "generate_spending_key should succeed");
        let sk_hex = result.unwrap();

        // An extended spending key is 169 bytes long, which is 338 hex characters.
        assert_eq!(sk_hex.len(), 338, "Spending key should have the correct hex length");
    }

    #[test]
    fn test_generate_spending_key_fails_on_short_seed() {
        let short_seed = "a1b2c3".to_string();
        let result = generate_spending_key(short_seed, 0);
        assert!(result.is_err(), "generate_spending_key should fail with a short seed");
    }

    #[test]
    fn test_z_getencryptionaddress_is_deterministic() {
        let params1 = RpcParams {
            seed: Some(TEST_SEED_HEX.to_string()),
            spending_key: None,
            hd_index: 1,
            encryption_index: 1,
            from_id: FROM_ID_HEX.to_string(),
            to_id: TO_ID_HEX.to_string(),
            return_secret: false,
        };
        let keys1 = z_getencryptionaddress(params1).expect("First key generation failed");

        let params2 = RpcParams {
            seed: Some(TEST_SEED_HEX.to_string()),
            spending_key: None,
            hd_index: 1,
            encryption_index: 1,
            from_id: FROM_ID_HEX.to_string(),
            to_id: TO_ID_HEX.to_string(),
            return_secret: false,
        };
        let keys2 = z_getencryptionaddress(params2).expect("Second key generation failed");

        assert_eq!(keys1.address, keys2.address, "Address should be deterministic");
        assert_eq!(keys1.fvk, keys2.fvk, "FVK should be deterministic");
    }

    #[test]
    fn test_z_getencryptionaddress_handles_return_secret_flag() {
        // return_secret = true
        let params_with_secret = RpcParams {
            seed: Some(TEST_SEED_HEX.to_string()),
            spending_key: None,
            hd_index: 2,
            encryption_index: 2,
            from_id: FROM_ID_HEX.to_string(),
            to_id: TO_ID_HEX.to_string(),
            return_secret: true,
        };
        let keys_with_secret = z_getencryptionaddress(params_with_secret).expect("Key gen with secret failed");
        assert!(keys_with_secret.spending_key.is_some(), "Spending key should be returned");

        // return_secret = false
        let params_without_secret = RpcParams {
            seed: Some(TEST_SEED_HEX.to_string()),
            spending_key: None,
            hd_index: 2,
            encryption_index: 2,
            from_id: FROM_ID_HEX.to_string(),
            to_id: TO_ID_HEX.to_string(),
            return_secret: false,
        };
        let keys_without_secret = z_getencryptionaddress(params_without_secret).expect("Key gen without secret failed");
        assert!(keys_without_secret.spending_key.is_none(), "Spending key should NOT be returned");
    }


    #[test]
    fn test_full_encryption_decryption_cycle() {

        // Generate keys for a recipient.
        let recipient_keys = setup_channel_keys();
        let original_message = "This is a secret message for the Verus Mobile SDK!".to_string();

        // encrypt a message to the recipient's address.
        let encrypted_payload_result = encrypt_message(
            recipient_keys.address.clone(),
            original_message.clone(),
            false, 
        );
        assert!(encrypted_payload_result.is_ok(), "Encryption should succeed");
        let encrypted_payload = encrypted_payload_result.unwrap();

        // decrypt the message using the recipient's Full Viewing Key (FVK).
        let decrypt_params = DecryptParams {
            fvk_hex: Some(recipient_keys.fvk),
            ephemeral_public_key_hex: Some(encrypted_payload.ephemeral_public_key),
            ciphertext_hex: encrypted_payload.ciphertext,
            symmetric_key_hex: None, // We are testing decryption with FVK
        };
        let decrypted_message_result = decrypt_message(decrypt_params);
        assert!(decrypted_message_result.is_ok(), "Decryption with FVK should succeed");

        // The decrypted message should match the original
        assert_eq!(decrypted_message_result.unwrap(), original_message);
    }

    #[test]
    fn test_decryption_with_symmetric_key() {
        // Generate keys for a recipient
        let recipient_keys = setup_channel_keys();
        let original_message = "Testing direct decryption with an SSK.".to_string();

        // Encrypt a message and ask for the symmetric key to be returned
        let encrypted_payload_result = encrypt_message(
            recipient_keys.address,
            original_message.clone(),
            true, // Return the symmetric key
        );
        assert!(encrypted_payload_result.is_ok(), "Encryption should succeed");
        let encrypted_payload = encrypted_payload_result.unwrap();
        assert!(encrypted_payload.symmetric_key.is_some(), "Symmetric key should be returned");

        // Decrypt the message using ONLY the returned symmetric key
        let decrypt_params = DecryptParams {
            fvk_hex: None, // FVK is not needed
            ephemeral_public_key_hex: None, // Ephemeral key is not needed
            ciphertext_hex: encrypted_payload.ciphertext,
            symmetric_key_hex: encrypted_payload.symmetric_key,
        };
        let decrypted_message_result = decrypt_message(decrypt_params);
        assert!(decrypted_message_result.is_ok(), "Decryption with SSK should succeed");

        // The decrypted message should match the original
        assert_eq!(decrypted_message_result.unwrap(), original_message);
    }
}