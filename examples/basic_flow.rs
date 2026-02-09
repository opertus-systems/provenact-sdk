use std::path::PathBuf;

use inactu_sdk::{ExecuteRequest, InactuSdk, SdkError, VerifyRequest};

fn main() -> Result<(), SdkError> {
    let sdk = InactuSdk::default();

    sdk.verify_bundle(VerifyRequest {
        bundle: PathBuf::from("./bundle"),
        keys: PathBuf::from("./public-keys.json"),
        keys_digest: Some("sha256:<public-keys-json-digest>".to_string()),
        require_cosign: false,
        oci_ref: None,
        allow_experimental: false,
    })?;

    let exec = sdk.execute_verified(ExecuteRequest {
        bundle: PathBuf::from("./bundle"),
        keys: PathBuf::from("./public-keys.json"),
        keys_digest: Some("sha256:<public-keys-json-digest>".to_string()),
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
