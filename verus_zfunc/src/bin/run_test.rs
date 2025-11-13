// In src/bin/run_test.rs
use verus_zfunc::{z_getencryptionaddress, RpcParams};

fn main() {
    println!("Running test for z_getencryptionaddress...");

    let params_simple = RpcParams {
        seed: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
        spending_key: None,
        hd_index: 0,
        encryption_index: 0,
        from_id: Some("237cc65dbb032174f0133e2f450f9afb5645e715".to_string()),
        to_id: None,
        //to_id: Some("ac57fe88ff9dbcc6562196fc6ba426d35d638366".to_string()),
        return_secret: true,
    };

    println!("\n=== Test 1 Results (with fromId) ===");
    match z_getencryptionaddress(params_simple) {
        Ok(channel_keys) => {
            println!("Address:      {}", channel_keys.address);
            println!("FVK:          {}", channel_keys.fvk);
            println!("IVK:          {}", channel_keys.ivk.unwrap_or_else(|| "Not returned".to_string()));
            println!("Spending Key: {}", channel_keys.spending_key.unwrap_or_else(|| "Not returned".to_string()));
        }
        Err(e) => println!("Error in Test 1: {}", e),
    }


     let params_no_ids = RpcParams {
        seed: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
        spending_key: None,
        hd_index: 0,
        encryption_index: 0,
        from_id: None,
        to_id: None,
        return_secret: true,
    };

     println!("\n=== Test 2 Results (no IDs) ===");
    match z_getencryptionaddress(params_no_ids) {
        Ok(channel_keys) => {
            println!("Address:      {}", channel_keys.address);
            println!("FVK:          {}", channel_keys.fvk);
            println!("IVK:          {}", channel_keys.ivk.unwrap_or_else(|| "Not returned".to_string()));
            println!("Spending Key: {}", channel_keys.spending_key.unwrap_or_else(|| "Not returned".to_string()));
        }
        Err(e) => println!("Error in Test 2: {}", e),
    }
}
