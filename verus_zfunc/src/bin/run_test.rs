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

    match z_getencryptionaddress(params_simple) {
        Ok(channel_keys) => {
            let daemon_address = "zs120e9xq89awhmvscegn9ezst7x9vt7asanwav2vaxwmlhum23peqjsrqnr6mx2lg7hmfmgy9psdy";
            println!("\n=== Test Results ===");
            println!("Address:        {}", channel_keys.address);
            println!("Daemon Address: {}", daemon_address);
            println!("Match:          {}", channel_keys.address == daemon_address);

            println!("FVK: {}", channel_keys.fvk);
            println!("IVK: {}", channel_keys.ivk.unwrap_or_default() )
        }
        Err(e) => println!("Error: {}", e),
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

    match z_getencryptionaddress(params_no_ids) {
        Ok(channel_keys) => {
            println!("\n=== Test 2 Results (no IDs) ===");
            println!("Address:        {}", channel_keys.address);
            println!("FVK:            {}", channel_keys.fvk);
            if let Some(sk) = channel_keys.spending_key {
                println!("Spending Key:   {}", sk);
            }
        }
        Err(e) => println!("Error in Test 2: {}", e),
    }
}
