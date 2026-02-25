use verus_zfunc::{z_getencryptionaddress, encrypt_data, decrypt, DecryptParams};
use secrecy::{SecretVec, Secret, ExposeSecret};
use hex;
use zcash_primitives::consensus::Network;
use zcash_keys::address::Address;
use zcash_keys::encoding::{encode_extended_spending_key, encode_extended_full_viewing_key};
use sapling::zip32::{ExtendedSpendingKey, ExtendedFullViewingKey};
use bs58;

fn iaddress_to_hash160(iaddress: &str) -> [u8; 20] {
    let decoded = bs58::decode(iaddress)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_vec()
        .unwrap();
    decoded[1..21].try_into().unwrap()
}


fn main() {
    let seed_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let seed_bytes = hex::decode(seed_hex).unwrap();
    let seed = SecretVec::new(seed_bytes);

    let from_id = iaddress_to_hash160("i94XrwNp9cMghEZ16fq7Fcd3XE57VNBWvo"); // neptune.cybermoney@
    let to_id   = iaddress_to_hash160("i4NpJp1vqrXgDvSNBXkNYvTR1VF2HMkeDA"); // mike@


    // ── Test 1: no IDs baseline ────────────────────────────────────────────────
    println!("\n=== Test 1: no IDs (baseline vs daemon) ===");
    match z_getencryptionaddress(
        Some(&seed), None, Some(0), Some(0),
        Some(&from_id), None,
        true,
    ) {
        Ok(channel_keys) => {
            println!("Address: {}", Address::from(channel_keys.address).encode(&Network::MainNetwork));
            println!("IVK:     {}", hex::encode(channel_keys.ivk_bytes.expose_secret()));

            if let Some(ref sk) = channel_keys.spending_key_bytes {
                match ExtendedSpendingKey::from_bytes(sk.expose_secret()) {
                    Ok(extsk) => println!("ExtSK:   {}", encode_extended_spending_key("secret-extended-key-main", &extsk)),
                    Err(_)    => println!("ExtSK:   failed to decode"),
                }
            }

            match ExtendedFullViewingKey::read(&mut channel_keys.extfvk_bytes.as_ref()) {
                Ok(extfvk) => println!("ExtFVK:  {}", encode_extended_full_viewing_key("zxviews", &extfvk)),
                Err(e)     => println!("ExtFVK:  failed to decode: {}", e),
            }
        }
        Err(e) => println!("Error in Test 1: {}", e),
    }

    // ── Test 2: both IDs (neptune.cybermoney@ → mike@) ────────────────────────
    println!("\n=== Test 2: neptune.cybermoney@ → mike@ ===");
    match z_getencryptionaddress(
        Some(&seed), None, Some(0), Some(0),
        Some(&from_id),
        Some(&to_id),
        true,
    ) {
        Ok(channel_keys) => {
            println!("Address: {}", Address::from(channel_keys.address).encode(&Network::MainNetwork));
            println!("IVK:     {}", hex::encode(channel_keys.ivk_bytes.expose_secret()));

            if let Some(ref sk) = channel_keys.spending_key_bytes {
                match ExtendedSpendingKey::from_bytes(sk.expose_secret()) {
                    Ok(extsk) => println!("ExtSK:   {}", encode_extended_spending_key("secret-extended-key-main", &extsk)),
                    Err(_)    => println!("ExtSK:   failed to decode"),
                }
            }

            match ExtendedFullViewingKey::read(&mut channel_keys.extfvk_bytes.as_ref()) {
                Ok(extfvk) => println!("ExtFVK:  {}", encode_extended_full_viewing_key("zxviews", &extfvk)),
                Err(e)     => println!("ExtFVK:  failed to decode: {}", e),
            }

            // ── Test 3: encrypt ────────────────────────────────────────────────
            println!("\n=== Test 3: encrypt_data ===");
            match encrypt_data(channel_keys.address, b"Hello Verus!", true) {
                Ok(payload) => {
                    println!("EPK:        {}", hex::encode(&payload.ephemeral_public_key));
                    println!("Ciphertext: {}", hex::encode(&payload.ciphertext));

                    println!("\n=== Test 4: decrypt (via SSK) ===");
                    let ssk_bytes = payload.symmetric_key.as_ref().map(|ssk| {
                        let bytes: [u8; 32] = ssk.as_slice().try_into().unwrap();
                        Secret::new(bytes)
                    });
                    println!("SSK:        {}", hex::encode(ssk_bytes.as_ref().unwrap().expose_secret()));

                    let params = DecryptParams {
                        extfvk_bytes: None,
                        epk_bytes: None,
                        ciphertext_hex: hex::encode(&payload.ciphertext),
                        symmetric_key_bytes: ssk_bytes,
                    };

                    match decrypt(params) {
                        Ok(msg) => println!("Decrypted: {}", String::from_utf8(msg).unwrap()),
                        Err(e)  => println!("Decrypt error: {}", e),
                    }
                }
                Err(e) => println!("Encrypt error: {}", e),
            }
        }
        Err(e) => println!("Error in Test 2: {}", e),
    }
}