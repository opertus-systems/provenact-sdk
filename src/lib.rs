use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, SdkError>;

#[derive(Debug, Clone)]
pub struct VerifyRequest {
    pub bundle: PathBuf,
    pub keys: PathBuf,
    pub keys_digest: Option<String>,
    pub require_cosign: bool,
    pub oci_ref: Option<String>,
    pub allow_experimental: bool,
}

#[derive(Debug, Clone)]
pub struct ExecuteRequest {
    pub bundle: PathBuf,
    pub keys: PathBuf,
    pub keys_digest: Option<String>,
    pub policy: PathBuf,
    pub input: PathBuf,
    pub receipt: PathBuf,
    pub require_cosign: bool,
    pub oci_ref: Option<String>,
    pub allow_experimental: bool,
}

#[derive(Debug, Clone)]
pub struct VerifyOutput {
    pub stdout: String,
}

#[derive(Debug, Clone)]
pub struct ExecuteOutput {
    pub stdout: String,
    pub receipt_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct Receipt {
    pub raw: Value,
}

#[derive(Debug, Error)]
pub enum SdkError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("provenact-cli command failed: {0}")]
    CommandFailed(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub trait CommandRunner {
    fn run<I, S>(&self, args: I) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>;
}

#[derive(Debug, Clone)]
pub struct CliRunner {
    bin: PathBuf,
}

impl Default for CliRunner {
    fn default() -> Self {
        Self {
            bin: PathBuf::from("provenact-cli"),
        }
    }
}

impl CliRunner {
    pub fn new(bin: impl AsRef<Path>) -> Self {
        Self {
            bin: bin.as_ref().to_path_buf(),
        }
    }
}

impl CommandRunner for CliRunner {
    fn run<I, S>(&self, args: I) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let collected: Vec<OsString> = args
            .into_iter()
            .map(|arg| arg.as_ref().to_os_string())
            .collect();
        let output = Command::new(&self.bin).args(&collected).output()?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let cmdline = collected
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(" ");
            let status = output.status.code().map_or_else(
                || "terminated-by-signal".to_string(),
                |code| code.to_string(),
            );
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(SdkError::CommandFailed(format!(
                "status={status} cmd=\"{} {cmdline}\" stdout=\"{stdout}\" stderr=\"{}\"",
                self.bin.display(),
                stderr.trim()
            )))
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProvenactSdk<R = CliRunner> {
    runner: R,
}

impl Default for ProvenactSdk<CliRunner> {
    fn default() -> Self {
        Self {
            runner: CliRunner::default(),
        }
    }
}

impl<R> ProvenactSdk<R>
where
    R: CommandRunner,
{
    pub fn with_runner(runner: R) -> Self {
        Self { runner }
    }

    pub fn verify_bundle(&self, req: VerifyRequest) -> Result<VerifyOutput> {
        validate_verify_request(&req)?;
        let keys_digest = resolve_keys_digest(req.keys_digest, &req.keys)?;

        let mut args = vec![
            "verify".to_string(),
            "--bundle".to_string(),
            req.bundle.display().to_string(),
            "--keys".to_string(),
            req.keys.display().to_string(),
        ];
        append_common_verify_flags(
            &mut args,
            Some(keys_digest),
            req.require_cosign,
            req.oci_ref,
            req.allow_experimental,
        );

        let stdout = self.runner.run(args)?;
        Ok(VerifyOutput { stdout })
    }

    pub fn execute_verified(&self, req: ExecuteRequest) -> Result<ExecuteOutput> {
        validate_execute_request(&req)?;
        let keys_digest = resolve_keys_digest(req.keys_digest, &req.keys)?;

        let mut args = vec![
            "run".to_string(),
            "--bundle".to_string(),
            req.bundle.display().to_string(),
            "--keys".to_string(),
            req.keys.display().to_string(),
            "--policy".to_string(),
            req.policy.display().to_string(),
            "--input".to_string(),
            req.input.display().to_string(),
            "--receipt".to_string(),
            req.receipt.display().to_string(),
        ];
        append_common_verify_flags(
            &mut args,
            Some(keys_digest),
            req.require_cosign,
            req.oci_ref,
            req.allow_experimental,
        );

        let stdout = self.runner.run(args)?;
        Ok(ExecuteOutput {
            stdout,
            receipt_path: req.receipt,
        })
    }

    pub fn parse_receipt(&self, path: impl AsRef<Path>) -> Result<Receipt> {
        let data = std::fs::read(path.as_ref())?;
        let raw: Value = serde_json::from_slice(&data)?;
        Ok(Receipt { raw })
    }
}

fn append_common_verify_flags(
    args: &mut Vec<String>,
    keys_digest: Option<String>,
    require_cosign: bool,
    oci_ref: Option<String>,
    allow_experimental: bool,
) {
    if let Some(digest) = keys_digest {
        args.push("--keys-digest".to_string());
        args.push(digest);
    }
    if require_cosign {
        args.push("--require-cosign".to_string());
    }
    if let Some(oci_ref) = oci_ref {
        args.push("--oci-ref".to_string());
        args.push(oci_ref);
    }
    if allow_experimental {
        args.push("--allow-experimental".to_string());
    }
}

fn validate_verify_request(req: &VerifyRequest) -> Result<()> {
    if req.require_cosign && req.oci_ref.is_none() {
        return Err(SdkError::InvalidRequest(
            "oci_ref is required when require_cosign is true".to_string(),
        ));
    }
    Ok(())
}

fn validate_execute_request(req: &ExecuteRequest) -> Result<()> {
    if req.require_cosign && req.oci_ref.is_none() {
        return Err(SdkError::InvalidRequest(
            "oci_ref is required when require_cosign is true".to_string(),
        ));
    }
    Ok(())
}

fn resolve_keys_digest(value: Option<String>, keys_path: &Path) -> Result<String> {
    match value {
        Some(digest) => Ok(digest),
        None => digest_file_sha256_prefixed(keys_path),
    }
}

fn digest_file_sha256_prefixed(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)?;
    let digest = Sha256::digest(&bytes);
    Ok(format!("sha256:{:x}", digest))
}

pub mod experimental {
    use super::*;

    pub fn validate_manifest_v1(
        runner: &impl CommandRunner,
        manifest: impl AsRef<Path>,
    ) -> Result<String> {
        runner.run([
            "experimental-validate-manifest-v1",
            "--manifest",
            &manifest.as_ref().display().to_string(),
        ])
    }

    pub fn validate_receipt_v1(
        runner: &impl CommandRunner,
        receipt: impl AsRef<Path>,
    ) -> Result<String> {
        runner.run([
            "experimental-validate-receipt-v1",
            "--receipt",
            &receipt.as_ref().display().to_string(),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeRunner {
        last_args: std::sync::Mutex<Vec<String>>,
    }

    impl CommandRunner for FakeRunner {
        fn run<I, S>(&self, args: I) -> Result<String>
        where
            I: IntoIterator<Item = S>,
            S: AsRef<OsStr>,
        {
            let collected = args
                .into_iter()
                .map(|a| a.as_ref().to_string_lossy().to_string())
                .collect::<Vec<_>>();
            *self.last_args.lock().expect("lock") = collected;
            Ok("OK".to_string())
        }
    }

    #[test]
    fn verify_builds_expected_args() {
        let runner = FakeRunner::default();
        let sdk = ProvenactSdk::with_runner(runner);

        let req = VerifyRequest {
            bundle: PathBuf::from("./bundle"),
            keys: PathBuf::from("./keys.json"),
            keys_digest: Some("sha256:abc".to_string()),
            require_cosign: true,
            oci_ref: Some("ghcr.io/acme/skill:1".to_string()),
            allow_experimental: true,
        };
        let _ = sdk.verify_bundle(req).expect("verify ok");

        let args = sdk.runner.last_args.lock().expect("lock").clone();
        assert!(args.starts_with(&[
            "verify".to_string(),
            "--bundle".to_string(),
            "./bundle".to_string(),
            "--keys".to_string(),
            "./keys.json".to_string()
        ]));
        assert!(args.contains(&"--keys-digest".to_string()));
        assert!(args.contains(&"sha256:abc".to_string()));
        assert!(args.contains(&"--require-cosign".to_string()));
        assert!(args.contains(&"--oci-ref".to_string()));
        assert!(args.contains(&"ghcr.io/acme/skill:1".to_string()));
        assert!(args.contains(&"--allow-experimental".to_string()));
    }

    #[test]
    fn execute_requires_oci_ref_when_cosign_required() {
        let runner = FakeRunner::default();
        let sdk = ProvenactSdk::with_runner(runner);
        let req = ExecuteRequest {
            bundle: PathBuf::from("./bundle"),
            keys: PathBuf::from("./keys.json"),
            keys_digest: None,
            policy: PathBuf::from("./policy.json"),
            input: PathBuf::from("./input.json"),
            receipt: PathBuf::from("./receipt.json"),
            require_cosign: true,
            oci_ref: None,
            allow_experimental: false,
        };

        let err = sdk.execute_verified(req).expect_err("must fail");
        assert!(matches!(err, SdkError::InvalidRequest(_)));
    }

    #[test]
    fn parse_receipt_reads_json() {
        let runner = FakeRunner::default();
        let sdk = ProvenactSdk::with_runner(runner);
        let dir = tempfile::tempdir().expect("tmp");
        let receipt_path = dir.path().join("receipt.json");
        std::fs::write(&receipt_path, r#"{"schema_version":"1.0.0"}"#).expect("write");

        let receipt = sdk.parse_receipt(&receipt_path).expect("parse");
        assert_eq!(receipt.raw["schema_version"], "1.0.0");
    }
}
