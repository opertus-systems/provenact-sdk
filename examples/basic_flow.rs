use std::path::PathBuf;

use provenact_sdk::{ExecuteRequest, ProvenactSdk, SdkError, VerifyRequest};

fn main() -> Result<(), SdkError> {
    let sdk = ProvenactSdk::default();

    sdk.verify_bundle(VerifyRequest {
        bundle: PathBuf::from("./bundle"),
        keys: PathBuf::from("./public-keys.json"),
        keys_digest: None,
        require_cosign: false,
        oci_ref: None,
        allow_experimental: false,
    })?;

    let exec = sdk.execute_verified(ExecuteRequest {
        bundle: PathBuf::from("./bundle"),
        keys: PathBuf::from("./public-keys.json"),
        keys_digest: None,
        policy: PathBuf::from("./policy.json"),
        input: PathBuf::from("./input.json"),
        receipt: PathBuf::from("./receipt.json"),
        require_cosign: false,
        oci_ref: None,
        allow_experimental: false,
    })?;

    let receipt = sdk.parse_receipt(exec.receipt_path)?;
    println!("receipt schema: {}", receipt.raw["schema_version"]);
    Ok(())
}
