use anyhow::{ Result, anyhow};
use chacha20poly1305::{ChaCha20Poly1305, aead::Aead, KeyInit};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use sapling::{
    Note, PaymentAddress, Rseed, SaplingIvk, note_encryption::{PreparedIncomingViewingKey, SaplingDomain}, value::NoteValue, zip32::ExtendedSpendingKey
};
use zcash_keys::address::Address;
use zcash_note_encryption::{Domain, EphemeralKeyBytes};
use zcash_primitives::{
    zip32::{ChildIndex, Scope},
};
use secrecy::{ExposeSecret, SecretVec, Secret};
use jubjub::Fr;

const VERUS_COIN_TYPE: u32 = 133;

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

pub struct ChannelKeys {
    pub address: PaymentAddress,
    pub extfvk_bytes: Secret<[u8; 169]>,
    pub spending_key_bytes: Option<Secret<[u8; 169]>>,
    pub ivk_bytes: Secret<[u8; 32]>, 
}

pub struct EncryptedPayload {
    pub ephemeral_public_key: [u8; 32],
    pub encrypted_data: Vec<u8>,
    pub symmetric_key: Option<Secret<[u8; 32]>>,
}

// derives a shared symmetric key using the receiver's private viewing key
// and the sender's public key

fn internal_get_symmetric_key_receiver(
    ivk_bytes: &Secret<[u8; 32]>,
    ephemeral_pk_bytes: &[u8; 32],
) -> Result<Secret<[u8; 32]>> {

    // we can use ivk_bytes direct to create the sapling ivk.
    let ivk = SaplingIvk(Option::<Fr>::from(Fr::from_bytes(ivk_bytes.expose_secret()))
        .ok_or_else(|| anyhow!("Failed to parse ivk bytes into SaplingIvk"))?);

    let sapling_ivk = PreparedIncomingViewingKey::new(&ivk);

    // parse the sender's public key bytes into a key object
    let epk_bytes = EphemeralKeyBytes(*ephemeral_pk_bytes);

    let epk = <SaplingDomain as Domain>::epk(&epk_bytes)
      .ok_or_else(|| anyhow!("Failed to create EphemeralPublicKey"))?;

    // prepare the public key
    let prepared_epk = <SaplingDomain as Domain>::prepare_epk(epk);

    // perform key agreement (ecdh) to calculate the shared secret
    let shared_secret = <SaplingDomain as Domain>::ka_agree_dec(&sapling_ivk, &prepared_epk);
    
    let symmetric_key = Secret::<[u8;32]>::new({
        <SaplingDomain as Domain>::kdf(shared_secret, &epk_bytes)
        .as_bytes()[..32].try_into()
        .map_err(|_| anyhow!("Failed to derive symmetric key: hash output is too short"))?
    });
    Ok(symmetric_key)
}


// this internal function generates a symmetric key from the sender's side
// it creates a temporary, single-use key pair and uses the recipient's public
// address to establish a shared secret

fn internal_generate_symmetric_key_sender(
    address: &Address,
) -> Result<(Secret<[u8; 32]>, EphemeralKeyBytes)> {

    let recipient = match address {
        Address::Sapling(addr) => addr,
        _ => return Err(anyhow!("Incompatible Address used")),
    };

    // generate fresh random bytes for the note's rseed

    //TODO: (Biz) I don't think we need any good rseed bytes here, AfterZip212 will generate (?)
    // leaving here for now, can't hurt
    let rseed_bytes = Secret::<[u8; 32]>::new({
        let mut tmp = [0u8; 32];
        getrandom::getrandom(&mut tmp)?;
        tmp
    });

    let rseed = Rseed::AfterZip212(*rseed_bytes.expose_secret());

    // necessary functions only available through Note struct
    let note = Note::from_parts(recipient.clone(), NoteValue::from_raw(0), rseed);

    // create a dummy rng to satisfy the function signature. this is not used for randomness.
    // (Biz) this is fine ONLY when we construct Rseed::AfterZip212 as above (!!)
    let mut dummy_rng = DummyRng;

    // generates a new, single-use ephemeral secret key (esk) deterministically from the rseed.
    // this is the sender's temporary private key for this one-time encryption.
    let esk = note.generate_or_derive_esk(&mut dummy_rng);

    let epk_bytes = <SaplingDomain as Domain>::epk_bytes(&<SaplingDomain as Domain>::ka_derive_public(&note, &esk));

    let shared_secret = <SaplingDomain as Domain>::ka_agree_enc(&esk, &recipient.pk_d());

    // derives the symmetric key using the shared secret and the ephemeral public key bytes
    let symmetric_key = Secret::<[u8; 32]>::new(
        <SaplingDomain as Domain>::kdf(shared_secret, &epk_bytes)
        .as_bytes()[..32].try_into()
        .map_err(|_| anyhow!("Failed to derive symmetric key: hash output is too short"))?
    );

    Ok((symmetric_key, epk_bytes))
}


// (Biz) the function below needs secured if anyone intends to use it.  It is not, as written

/*pub fn generate_spending_key(seed_hex: String, hd_index: u32) -> Result<String> {
    let seed_bytes = hex::decode(seed_hex)?;
    if seed_bytes.len() < 32 {
        return Err(anyhow!("Seed must be at least 32 bytes"));
    }

    // perform the BIP-44 derivation as your main function

    let master_sk = ExtendedSpendingKey::master(&seed_bytes);
    let purpose_key = master_sk.derive_child(ChildIndex::hardened(32));
    let coin_type_key = purpose_key.derive_child(ChildIndex::hardened(VERUS_COIN_TYPE));
    let account_sk = coin_type_key.derive_child(ChildIndex::hardened(hd_index));

    // serialize the derived key to bytes
    let mut sk_bytes = Vec::new();
    account_sk.write(&mut sk_bytes)?;

    // return the hex-encoded spending key
    Ok(hex::encode(sk_bytes))
}
*/

// generates a unique, deterministic encryption address for a communication channel
// between two parties, identified by from_id` and `to_id
pub fn z_getencryptionaddress(
    seed: Option<&SecretVec<u8>>,  //TODO: create enum that combines seed & spending key in this layer into SeedMaterial variants
    spending_key: Option<&Secret<[u8; 169]>>,
    hd_index: Option<u32>,  //TODO: then combine hd_index with seed, to eliminate hd_index logic when extsk present
    encryption_index: Option<u32>, // should be optional, 
    from_id: Option<&[u8; 20]>,
    to_id: Option<&[u8; 20]>,
    return_secret: bool,
) -> Result<ChannelKeys> {
    // immediately pack the computed spending key (derived from seed OR directly extsk) into a secret array
    let base_sk = Secret::<[u8; 169]>::new(
        if let Some(seed_bytes) = seed.as_ref() {
            // if a seed is provided, derive the account key using the hd_index
            match seed_bytes.expose_secret().len() {
                32 | 64 => {  // valid values for seed length 32, or 64 bytes
                    // derive base spending key fixed path m/32'/coin_type'/hd_index'
                    let master_sk = ExtendedSpendingKey::master(seed_bytes.expose_secret().as_slice())
                        .derive_child(ChildIndex::hardened(32))
                        .derive_child(ChildIndex::hardened(VERUS_COIN_TYPE));
                    if let Some(hd_index) = hd_index {
                        master_sk.derive_child(ChildIndex::hardened(hd_index)).to_bytes()
                    } else {
                        // 0 used as default index when not provided
                        master_sk.derive_child(ChildIndex::hardened(0)).to_bytes()
                    }
                },
                0 => {
                    return Err(anyhow!("An empty string was passed as seed! If this was intentional, pass null argument instead on higher level"))
                }
                _ => {
                    // all other lengths throw erorr
                    return Err(anyhow!("If present, a seed for encryption address must be 32 or 64 bytes (hex)"));
                }
            }
        } else if let Some(extsk_bytes) = spending_key.as_ref() {
            // if a spending key is provided, use it directly
            if hd_index.is_some() {
                return Err(anyhow!("Spending key, and hdindex provided! If an hdindex is provided, seed must be an HD wallet seed for which (hdindex) represents a valid address index!"));
            }
            // length check for 169 happens inside from_bytes()
            ExtendedSpendingKey::from_bytes(extsk_bytes.expose_secret())
                .map_err(|_| anyhow!("Failed to parse spending key"))?.to_bytes()
        } else {
            return Err(anyhow!("Must provide 'seed' or 'spendingKey'"));
        }
    );

    // we compute a sha256 hash, and immediately pack this variable into a new secret array
    let encryption_channel_seed: Secret<[u8; 32]> = Secret::new({
        let mut seed_hash = Sha256::new();
        //only expose base_sk Secret inside this scope
        seed_hash.update(base_sk.expose_secret());

        // serialize id bytes portion of seed, 0 is used in place if absent
        if let Some(from_id_bytes) = from_id {
            seed_hash.update(from_id_bytes);
        } else {
            seed_hash.update(&[0u8]);
        }
        if let Some(to_id_bytes) = to_id {
            seed_hash.update(to_id_bytes);
        } 
 
        seed_hash.finalize().into()
    });

    let (payment_address, channel_sk, extfvk_bytes, ivk_bytes) = {
        let channel_secret_key = ExtendedSpendingKey::master(encryption_channel_seed.expose_secret())
            .derive_child(ChildIndex::hardened(32))
            .derive_child(ChildIndex::hardened(VERUS_COIN_TYPE))
            .derive_child(ChildIndex::hardened(encryption_index.unwrap_or(0)));

        let extfvk_serialized: Secret<[u8; 169]> = Secret::new({
            let mut tmp = [0u8; 169];
            let mut w = std::io::Cursor::new(tmp.as_mut_slice());
            channel_secret_key
                .to_extended_full_viewing_key()
                .write(&mut w)
                .map_err(|_| anyhow!("Failed to serialize extfvk"))?;
            // check we have a complete write
            let written = w.position() as usize;
            if written != tmp.len() {
                return Err(anyhow!(
                    "Unexpected extfvk length: wrote {} bytes, expected {}",
                     written,
                     tmp.len()
                ));
            }
           // TODO: maybe find a way to zeroize this intermediate (not urgent)
           tmp
        });

        let dfvk = channel_secret_key.to_diversifiable_full_viewing_key();

        let (_/*diversifier*/, address) = dfvk.default_address();

        // get the ivk_bytes directly from the dfvk
        let derived_ivk_bytes = Secret::<[u8; 32]>::new(dfvk.to_ivk(Scope::External).0.to_bytes());

        let spending_key_bytes = if return_secret {
            Some(Secret::new(channel_secret_key.to_bytes()))
        } else {
            None
        };

        (address, spending_key_bytes, extfvk_serialized, derived_ivk_bytes)
    };
    
    let channel_keys = ChannelKeys {
        address: payment_address,
        extfvk_bytes: extfvk_bytes,
        spending_key_bytes: channel_sk,
        ivk_bytes: ivk_bytes
    };

    Ok(channel_keys)
}


// encrypts a buffer of data for a given zcash address
pub fn encrypt_data(
    encrypt_address: &PaymentAddress,
    data_to_encrypt: &SecretVec<u8>,
    return_ssk: bool,
) -> Result<EncryptedPayload> {
    // decode the address string into a structured address object
    let addr = Address::Sapling(*encrypt_address);

    // call the internal helper to perform the key exchange
    // this returns the shared symmetric key and the public ephemeral key
    let (key_bytes, epk_bytes) =
        internal_generate_symmetric_key_sender(&addr)?;

    let encrypted_data: Vec<u8> = {
        // initialize the chacha20poly1305 cipher with the 32-byte key
        let encrypt = ChaCha20Poly1305::new_from_slice(key_bytes.expose_secret())
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;
        let nonce = chacha20poly1305::Nonce::default();

        // encrypt the buffer, allowing ChaCha20Poly1305 to allocate, using the cipher and nonce
        // doing this NOT in-place, results in only allocating for the bytes we have actually encrypted
        encrypt
            .encrypt(&nonce, data_to_encrypt.expose_secret().as_slice())
            .map_err(|_| anyhow!("Encryption failed"))?
    };

    // prepare the decrypted payload to be returned
    let result = EncryptedPayload {
        ephemeral_public_key: epk_bytes.0,
        encrypted_data: encrypted_data,
        symmetric_key: if return_ssk {
            // Return the 32-byte key that was actually used for encryption if requested
            Some(key_bytes)
        } else {
            None
        },
    };

    Ok(result)
}

// decrypts a buffer using either a direct symmetric key, or by deriving
// the incoming viewing key and the senders ephemeral public key
pub fn decrypt_data(
    ivk_bytes: Option<&Secret<[u8;32]>>,
    epk_bytes: Option<&[u8; 32]>,
    data_to_decrypt: &SecretVec<u8>,
    symmetric_key_bytes: Option<&Secret<[u8; 32]>>
) -> Result<SecretVec<u8>> {    
    let key_bytes: Secret<[u8; 32]> = if let Some (ssk_bytes) = symmetric_key_bytes.as_ref() 
    {
        Secret::new(*ssk_bytes.expose_secret())
    } else if let (Some(ivk_bytes), Some(epk_bytes)) = (
        ivk_bytes.as_ref(),
        epk_bytes.as_ref()
    ){
        // reference and generate a symmetric key
        internal_get_symmetric_key_receiver(ivk_bytes, epk_bytes)?
    }
    else{
        return Err(anyhow!("Must provide either a symmetric key or both ivk and epk bytes"));
    };
    
    let decrypted_data = SecretVec::new({
        // initialize the chacha20poly1305 cipher with the 32-byte key
        let decrypt = ChaCha20Poly1305::new_from_slice(&key_bytes.expose_secret().as_slice())
            .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;
        let nonce = chacha20poly1305::Nonce::default();

        // decrypt the data. we don't do so in-place, to avoid cloning. this will fail if the key is incorrect.
        // this way we don't make copies, and only allocate for bytes we have actually decrypted
        decrypt
            .decrypt(&nonce, data_to_decrypt.expose_secret().as_slice())
            .map_err(|_| anyhow!("Decryption failed. Key or ciphertext may be incorrect."))?
   });

    // if decryption is successful, return the decrypted data as a vector of bytes, packed into secret
   Ok(decrypted_data)
}

