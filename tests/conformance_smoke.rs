use std::path::{Path, PathBuf};
use std::process::Command;

use inactu_sdk::{CliRunner, InactuSdk, VerifyRequest};

#[test]
fn verify_good_vector_smoke() {
    let Ok(root) = discover_inactu_root() else {
        eprintln!("skipping smoke: no local inactu checkout configured");
        return;
    };
    let cli_bin = discover_or_build_inactu_cli(&root).expect("discover/build inactu-cli");
    let sdk = InactuSdk::with_runner(CliRunner::new(cli_bin));

    sdk.verify_bundle(VerifyRequest {
        bundle: root.join("test-vectors/good/minimal-zero-cap"),
        keys: root.join("test-vectors/good/minimal-zero-cap/public-keys.json"),
        keys_digest: None,
        require_cosign: false,
        oci_ref: None,
        allow_experimental: false,
    })
    .expect("verify should pass");
}

fn discover_inactu_root() -> Result<PathBuf, String> {
    if let Ok(root) = std::env::var("INACTU_VECTOR_ROOT") {
        return Ok(PathBuf::from(root));
    }
    let fallback = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| "workspace parent not found".to_string())?
        .join("inactu");
    if fallback.is_dir() {
        Ok(fallback)
    } else {
        Err(
            "INACTU_VECTOR_ROOT not set and sibling ../inactu not found; cannot run smoke test"
                .to_string(),
        )
    }
}

fn discover_or_build_inactu_cli(root: &Path) -> Result<PathBuf, String> {
    if let Ok(cli) = std::env::var("INACTU_CLI_BIN") {
        return Ok(PathBuf::from(cli));
    }

    let candidate = root.join("target/debug/inactu-cli");
    if candidate.is_file() {
        return Ok(candidate);
    }

    let output = Command::new("cargo")
        .arg("build")
        .arg("-p")
        .arg("inactu-cli")
        .current_dir(root)
        .output()
        .map_err(|e| format!("failed to invoke cargo build for inactu-cli: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "building inactu-cli failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(candidate)
}
