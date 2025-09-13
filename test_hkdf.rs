use aws_lc_rs::hkdf;

fn main() {
    let salt = b"salt";
    let ikm = b"input key material";
    let info = b"info";
    
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(ikm);
    
    // Try expand with just info
    println!("Testing expand with just info...");
    match prk.expand(&[info], hkdf::HKDF_SHA256) {
        Ok(okm) => {
            let mut output = vec![0u8; 64];
            match okm.fill(&mut output) {
                Ok(_) => println!("Success with algorithm parameter!"),
                Err(e) => println!("Fill failed: {:?}", e),
            }
        }
        Err(e) => println!("Expand failed with algorithm: {:?}", e),
    }
}
