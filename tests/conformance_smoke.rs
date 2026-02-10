use std::path::{Path, PathBuf};
use std::process::Command;

use provenact_sdk::{CliRunner, ProvenactSdk, VerifyRequest};
use sha2::Digest as _;

#[test]
fn verify_good_vector_smoke() {
    let Ok(root) = discover_provenact_root() else {
        eprintln!("skipping smoke: no local provenact checkout configured");
        return;
    };
    let cli_bin = discover_or_build_provenact_cli(&root).expect("discover/build provenact-cli");
    let sdk = ProvenactSdk::with_runner(CliRunner::new(cli_bin));
    let keys = root.join("test-vectors/good/minimal-zero-cap/public-keys.json");
    let keys_digest = sha256_file(&keys).expect("keys digest should compute");

    sdk.verify_bundle(VerifyRequest {
        bundle: root.join("test-vectors/good/minimal-zero-cap"),
        keys,
        keys_digest: Some(keys_digest),
        require_cosign: false,
        oci_ref: None,
        allow_experimental: false,
    })
    .expect("verify should pass");
}

fn discover_provenact_root() -> Result<PathBuf, String> {
    if let Ok(root) = std::env::var("PROVENACT_VECTOR_ROOT") {
        return Ok(PathBuf::from(root));
    }
    let fallback = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| "workspace parent not found".to_string())?
        .join("provenact");
    if fallback.is_dir() {
        Ok(fallback)
    } else {
        Err(
            "PROVENACT_VECTOR_ROOT not set and sibling ../provenact not found; cannot run smoke test"
                .to_string(),
        )
    }
}

fn discover_or_build_provenact_cli(root: &Path) -> Result<PathBuf, String> {
    if let Ok(cli) = std::env::var("PROVENACT_CLI_BIN") {
        return Ok(PathBuf::from(cli));
    }

    let candidate = root.join("target/debug/provenact-cli");
    if candidate.is_file() {
        return Ok(candidate);
    }

    let output = Command::new("cargo")
        .arg("build")
        .arg("-p")
        .arg("provenact-cli")
        .current_dir(root)
        .output()
        .map_err(|e| format!("failed to invoke cargo build for provenact-cli: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "building provenact-cli failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(candidate)
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    Ok(format!("sha256:{:x}", sha2::Sha256::digest(bytes)))
}
