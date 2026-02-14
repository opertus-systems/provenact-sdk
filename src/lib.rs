use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, SdkError>;
const SHA256_HEX_LEN: usize = 64;
const MAX_RECEIPT_BYTES: u64 = 1_048_576;

#[derive(Debug, Clone)]
pub struct VerifyRequest {
    pub bundle: PathBuf,
    pub keys: PathBuf,
    pub keys_digest: Option<String>,
    pub require_cosign: bool,
    pub oci_ref: Option<String>,
    pub cosign_key: Option<PathBuf>,
    pub cosign_cert_identity: Option<String>,
    pub cosign_cert_oidc_issuer: Option<String>,
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
    pub cosign_key: Option<PathBuf>,
    pub cosign_cert_identity: Option<String>,
    pub cosign_cert_oidc_issuer: Option<String>,
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
        let allow_path_bin = std::env::var("PROVENACT_ALLOW_PATH_CLI")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        validate_cli_binary_path(&self.bin, allow_path_bin)?;
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
        validate_required_path(&req.bundle, "bundle", "verify_bundle")?;
        validate_required_path(&req.keys, "keys", "verify_bundle")?;
        let keys_digest = validate_request(&req, "verify_bundle")?;

        let mut args = vec![
            "verify".to_string(),
            "--bundle".to_string(),
            req.bundle.display().to_string(),
            "--keys".to_string(),
            req.keys.display().to_string(),
            "--keys-digest".to_string(),
            keys_digest,
        ];
        append_common_flags(&mut args, &req);

        let stdout = self.runner.run(args)?;
        Ok(VerifyOutput { stdout })
    }

    pub fn execute_verified(&self, req: ExecuteRequest) -> Result<ExecuteOutput> {
        validate_required_path(&req.bundle, "bundle", "execute_verified")?;
        validate_required_path(&req.keys, "keys", "execute_verified")?;
        validate_required_path(&req.policy, "policy", "execute_verified")?;
        validate_required_path(&req.input, "input", "execute_verified")?;
        validate_required_path(&req.receipt, "receipt", "execute_verified")?;
        let keys_digest = validate_request(&req, "execute_verified")?;

        let mut args = vec![
            "run".to_string(),
            "--bundle".to_string(),
            req.bundle.display().to_string(),
            "--keys".to_string(),
            req.keys.display().to_string(),
            "--keys-digest".to_string(),
            keys_digest,
            "--policy".to_string(),
            req.policy.display().to_string(),
            "--input".to_string(),
            req.input.display().to_string(),
            "--receipt".to_string(),
            req.receipt.display().to_string(),
        ];
        append_common_flags(&mut args, &req);

        let stdout = self.runner.run(args)?;
        Ok(ExecuteOutput {
            stdout,
            receipt_path: req.receipt,
        })
    }

    pub fn parse_receipt(&self, path: impl AsRef<Path>) -> Result<Receipt> {
        let path = path.as_ref();
        validate_required_path(path, "receipt", "parse_receipt")?;
        let file = std::fs::File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(SdkError::InvalidRequest(
                "receipt path must point to a regular file".to_string(),
            ));
        }
        if metadata.len() > MAX_RECEIPT_BYTES {
            return Err(SdkError::InvalidRequest(format!(
                "receipt file exceeds maximum size of {MAX_RECEIPT_BYTES} bytes"
            )));
        }
        let mut reader = file.take(MAX_RECEIPT_BYTES + 1);
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        if data.len() as u64 > MAX_RECEIPT_BYTES {
            return Err(SdkError::InvalidRequest(format!(
                "receipt file exceeds maximum size of {MAX_RECEIPT_BYTES} bytes"
            )));
        }
        let raw: Value = serde_json::from_slice(&data)?;
        Ok(Receipt { raw })
    }
}

trait CommonRequest {
    fn keys_digest(&self) -> Option<&str>;
    fn require_cosign(&self) -> bool;
    fn oci_ref(&self) -> Option<&str>;
    fn cosign_key(&self) -> Option<&Path>;
    fn cosign_cert_identity(&self) -> Option<&str>;
    fn cosign_cert_oidc_issuer(&self) -> Option<&str>;
    fn allow_experimental(&self) -> bool;
}

impl CommonRequest for VerifyRequest {
    fn keys_digest(&self) -> Option<&str> {
        self.keys_digest.as_deref()
    }

    fn require_cosign(&self) -> bool {
        self.require_cosign
    }

    fn oci_ref(&self) -> Option<&str> {
        self.oci_ref.as_deref()
    }

    fn cosign_key(&self) -> Option<&Path> {
        self.cosign_key.as_deref()
    }

    fn cosign_cert_identity(&self) -> Option<&str> {
        self.cosign_cert_identity.as_deref()
    }

    fn cosign_cert_oidc_issuer(&self) -> Option<&str> {
        self.cosign_cert_oidc_issuer.as_deref()
    }

    fn allow_experimental(&self) -> bool {
        self.allow_experimental
    }
}

impl CommonRequest for ExecuteRequest {
    fn keys_digest(&self) -> Option<&str> {
        self.keys_digest.as_deref()
    }

    fn require_cosign(&self) -> bool {
        self.require_cosign
    }

    fn oci_ref(&self) -> Option<&str> {
        self.oci_ref.as_deref()
    }

    fn cosign_key(&self) -> Option<&Path> {
        self.cosign_key.as_deref()
    }

    fn cosign_cert_identity(&self) -> Option<&str> {
        self.cosign_cert_identity.as_deref()
    }

    fn cosign_cert_oidc_issuer(&self) -> Option<&str> {
        self.cosign_cert_oidc_issuer.as_deref()
    }

    fn allow_experimental(&self) -> bool {
        self.allow_experimental
    }
}

fn non_empty_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

fn has_non_empty_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
}

fn validate_required_path(path: &Path, field: &str, operation: &str) -> Result<()> {
    if !has_non_empty_path(path) {
        return Err(SdkError::InvalidRequest(format!(
            "{field} path is required for {operation}"
        )));
    }
    Ok(())
}

fn validate_request(req: &impl CommonRequest, operation: &str) -> Result<String> {
    let Some(keys_digest) = non_empty_trimmed(req.keys_digest()) else {
        return Err(SdkError::InvalidRequest(format!(
            "keys_digest is required for {operation}"
        )));
    };
    if !is_valid_sha256_prefixed_hex(&keys_digest) {
        return Err(SdkError::InvalidRequest(
            "keys_digest must match sha256:<64 lowercase hex>".to_string(),
        ));
    }

    if !req.require_cosign() {
        return Ok(keys_digest);
    }

    if non_empty_trimmed(req.oci_ref()).is_none() {
        return Err(SdkError::InvalidRequest(
            "oci_ref is required when require_cosign is true".to_string(),
        ));
    }
    let Some(cosign_key) = req.cosign_key() else {
        return Err(SdkError::InvalidRequest(
            "cosign_key is required when require_cosign is true".to_string(),
        ));
    };
    if !has_non_empty_path(cosign_key) {
        return Err(SdkError::InvalidRequest(
            "cosign_key must not be an empty path".to_string(),
        ));
    }
    if non_empty_trimmed(req.cosign_cert_identity()).is_none() {
        return Err(SdkError::InvalidRequest(
            "cosign_cert_identity is required when require_cosign is true".to_string(),
        ));
    }
    if non_empty_trimmed(req.cosign_cert_oidc_issuer()).is_none() {
        return Err(SdkError::InvalidRequest(
            "cosign_cert_oidc_issuer is required when require_cosign is true".to_string(),
        ));
    }
    Ok(keys_digest)
}

fn append_common_flags(args: &mut Vec<String>, req: &impl CommonRequest) {
    if req.require_cosign() {
        args.push("--require-cosign".to_string());
    }
    if let Some(oci_ref) = non_empty_trimmed(req.oci_ref()) {
        args.push("--oci-ref".to_string());
        args.push(oci_ref);
    }
    if let Some(cosign_key) = req.cosign_key().filter(|path| has_non_empty_path(path)) {
        args.push("--cosign-key".to_string());
        args.push(cosign_key.display().to_string());
    }
    if let Some(cosign_cert_identity) = non_empty_trimmed(req.cosign_cert_identity()) {
        args.push("--cosign-cert-identity".to_string());
        args.push(cosign_cert_identity);
    }
    if let Some(cosign_cert_oidc_issuer) = non_empty_trimmed(req.cosign_cert_oidc_issuer()) {
        args.push("--cosign-cert-oidc-issuer".to_string());
        args.push(cosign_cert_oidc_issuer);
    }
    if req.allow_experimental() {
        args.push("--allow-experimental".to_string());
    }
}

fn is_valid_sha256_prefixed_hex(value: &str) -> bool {
    let Some(digest_hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    digest_hex.len() == SHA256_HEX_LEN
        && digest_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_cli_binary_path(bin: &Path, allow_path_bin: bool) -> Result<()> {
    if bin.is_absolute() {
        return Ok(());
    }
    if !allow_path_bin {
        return Err(SdkError::InvalidRequest(
            "CliRunner binary must be an absolute path; set PROVENACT_ALLOW_PATH_CLI=1 to opt into PATH lookup".to_string(),
        ));
    }
    let mut components = bin.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err(SdkError::InvalidRequest(
            "CliRunner binary must be a simple command name when PROVENACT_ALLOW_PATH_CLI=1"
                .to_string(),
        )),
    }
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
    const TEST_KEYS_DIGEST: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

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
            keys_digest: Some(TEST_KEYS_DIGEST.to_string()),
            require_cosign: true,
            oci_ref: Some("ghcr.io/acme/skill:1".to_string()),
            cosign_key: Some(PathBuf::from("./cosign.pub")),
            cosign_cert_identity: Some(
                "https://github.com/acme/workflow@refs/heads/main".to_string(),
            ),
            cosign_cert_oidc_issuer: Some(
                "https://token.actions.githubusercontent.com".to_string(),
            ),
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
        assert!(args.contains(&TEST_KEYS_DIGEST.to_string()));
        assert!(args.contains(&"--require-cosign".to_string()));
        assert!(args.contains(&"--oci-ref".to_string()));
        assert!(args.contains(&"ghcr.io/acme/skill:1".to_string()));
        assert!(args.contains(&"--cosign-key".to_string()));
        assert!(args.contains(&"./cosign.pub".to_string()));
        assert!(args.contains(&"--cosign-cert-identity".to_string()));
        assert!(args.contains(&"https://github.com/acme/workflow@refs/heads/main".to_string()));
        assert!(args.contains(&"--cosign-cert-oidc-issuer".to_string()));
        assert!(args.contains(&"https://token.actions.githubusercontent.com".to_string()));
        assert!(args.contains(&"--allow-experimental".to_string()));
    }

    #[test]
    fn verify_trims_keys_digest_before_forwarding() {
        let runner = FakeRunner::default();
        let sdk = ProvenactSdk::with_runner(runner);

        let req = VerifyRequest {
            bundle: PathBuf::from("./bundle"),
            keys: PathBuf::from("./keys.json"),
            keys_digest: Some(format!("  {TEST_KEYS_DIGEST}  ")),
            require_cosign: false,
            oci_ref: None,
            cosign_key: None,
            cosign_cert_identity: None,
            cosign_cert_oidc_issuer: None,
            allow_experimental: false,
        };
        let _ = sdk.verify_bundle(req).expect("verify ok");

        let args = sdk.runner.last_args.lock().expect("lock").clone();
        let digest_index = args
            .iter()
            .position(|arg| arg == "--keys-digest")
            .expect("keys digest flag should be present");
        assert_eq!(args[digest_index + 1], TEST_KEYS_DIGEST);
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
            cosign_key: None,
            cosign_cert_identity: None,
            cosign_cert_oidc_issuer: None,
            allow_experimental: false,
        };

        let err = sdk.execute_verified(req).expect_err("must fail");
        assert!(matches!(err, SdkError::InvalidRequest(_)));
    }

    #[test]
    fn verify_rejects_blank_keys_digest() {
        let runner = FakeRunner::default();
        let sdk = ProvenactSdk::with_runner(runner);

        let req = VerifyRequest {
            bundle: PathBuf::from("./bundle"),
            keys: PathBuf::from("./keys.json"),
            keys_digest: Some("   ".to_string()),
            require_cosign: false,
            oci_ref: None,
            cosign_key: None,
            cosign_cert_identity: None,
            cosign_cert_oidc_issuer: None,
            allow_experimental: false,
        };

        let err = sdk.verify_bundle(req).expect_err("must fail");
        assert!(matches!(err, SdkError::InvalidRequest(_)));
    }

    #[test]
    fn verify_rejects_invalid_keys_digest_format() {
        let runner = FakeRunner::default();
        let sdk = ProvenactSdk::with_runner(runner);

        let req = VerifyRequest {
            bundle: PathBuf::from("./bundle"),
            keys: PathBuf::from("./keys.json"),
            keys_digest: Some("sha256:xyz".to_string()),
            require_cosign: false,
            oci_ref: None,
            cosign_key: None,
            cosign_cert_identity: None,
            cosign_cert_oidc_issuer: None,
            allow_experimental: false,
        };

        let err = sdk.verify_bundle(req).expect_err("must fail");
        assert!(matches!(err, SdkError::InvalidRequest(_)));
    }

    #[test]
    fn verify_rejects_empty_bundle_path() {
        let runner = FakeRunner::default();
        let sdk = ProvenactSdk::with_runner(runner);

        let req = VerifyRequest {
            bundle: PathBuf::new(),
            keys: PathBuf::from("./keys.json"),
            keys_digest: Some(TEST_KEYS_DIGEST.to_string()),
            require_cosign: false,
            oci_ref: None,
            cosign_key: None,
            cosign_cert_identity: None,
            cosign_cert_oidc_issuer: None,
            allow_experimental: false,
        };

        let err = sdk.verify_bundle(req).expect_err("must fail");
        assert!(matches!(err, SdkError::InvalidRequest(_)));
    }

    #[test]
    fn execute_rejects_blank_oci_ref_when_cosign_required() {
        let runner = FakeRunner::default();
        let sdk = ProvenactSdk::with_runner(runner);
        let req = ExecuteRequest {
            bundle: PathBuf::from("./bundle"),
            keys: PathBuf::from("./keys.json"),
            keys_digest: Some(TEST_KEYS_DIGEST.to_string()),
            policy: PathBuf::from("./policy.json"),
            input: PathBuf::from("./input.json"),
            receipt: PathBuf::from("./receipt.json"),
            require_cosign: true,
            oci_ref: Some(" ".to_string()),
            cosign_key: Some(PathBuf::from("./cosign.pub")),
            cosign_cert_identity: Some(
                "https://github.com/acme/workflow@refs/heads/main".to_string(),
            ),
            cosign_cert_oidc_issuer: Some(
                "https://token.actions.githubusercontent.com".to_string(),
            ),
            allow_experimental: false,
        };

        let err = sdk.execute_verified(req).expect_err("must fail");
        assert!(matches!(err, SdkError::InvalidRequest(_)));
    }

    #[test]
    fn execute_rejects_empty_receipt_path() {
        let runner = FakeRunner::default();
        let sdk = ProvenactSdk::with_runner(runner);
        let req = ExecuteRequest {
            bundle: PathBuf::from("./bundle"),
            keys: PathBuf::from("./keys.json"),
            keys_digest: Some(TEST_KEYS_DIGEST.to_string()),
            policy: PathBuf::from("./policy.json"),
            input: PathBuf::from("./input.json"),
            receipt: PathBuf::new(),
            require_cosign: false,
            oci_ref: None,
            cosign_key: None,
            cosign_cert_identity: None,
            cosign_cert_oidc_issuer: None,
            allow_experimental: false,
        };

        let err = sdk.execute_verified(req).expect_err("must fail");
        assert!(matches!(err, SdkError::InvalidRequest(_)));
    }

    #[test]
    fn execute_rejects_empty_cosign_key_path_when_required() {
        let runner = FakeRunner::default();
        let sdk = ProvenactSdk::with_runner(runner);
        let req = ExecuteRequest {
            bundle: PathBuf::from("./bundle"),
            keys: PathBuf::from("./keys.json"),
            keys_digest: Some(TEST_KEYS_DIGEST.to_string()),
            policy: PathBuf::from("./policy.json"),
            input: PathBuf::from("./input.json"),
            receipt: PathBuf::from("./receipt.json"),
            require_cosign: true,
            oci_ref: Some("ghcr.io/acme/skill:1".to_string()),
            cosign_key: Some(PathBuf::new()),
            cosign_cert_identity: Some(
                "https://github.com/acme/workflow@refs/heads/main".to_string(),
            ),
            cosign_cert_oidc_issuer: Some(
                "https://token.actions.githubusercontent.com".to_string(),
            ),
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

    #[test]
    fn parse_receipt_rejects_empty_path() {
        let runner = FakeRunner::default();
        let sdk = ProvenactSdk::with_runner(runner);

        let err = sdk.parse_receipt(PathBuf::new()).expect_err("must fail");
        assert!(matches!(err, SdkError::InvalidRequest(_)));
    }

    #[test]
    fn parse_receipt_rejects_oversized_file() {
        let runner = FakeRunner::default();
        let sdk = ProvenactSdk::with_runner(runner);
        let dir = tempfile::tempdir().expect("tmp");
        let receipt_path = dir.path().join("receipt.json");
        std::fs::write(&receipt_path, vec![b'x'; (MAX_RECEIPT_BYTES as usize) + 1]).expect("write");

        let err = sdk.parse_receipt(&receipt_path).expect_err("must fail");
        assert!(matches!(err, SdkError::InvalidRequest(_)));
    }

    #[test]
    fn parse_receipt_accepts_file_at_size_limit() {
        let runner = FakeRunner::default();
        let sdk = ProvenactSdk::with_runner(runner);
        let dir = tempfile::tempdir().expect("tmp");
        let receipt_path = dir.path().join("receipt.json");

        let mut payload = String::from("{\"payload\":\"");
        payload.push_str(&"x".repeat((MAX_RECEIPT_BYTES as usize) - payload.len() - 2));
        payload.push_str("\"}");
        assert_eq!(payload.len(), MAX_RECEIPT_BYTES as usize);
        std::fs::write(&receipt_path, payload.as_bytes()).expect("write");

        let receipt = sdk.parse_receipt(&receipt_path).expect("parse");
        assert!(receipt.raw.get("payload").is_some());
    }

    #[test]
    fn cli_binary_validation_requires_absolute_path_without_opt_in() {
        let err =
            validate_cli_binary_path(Path::new("provenact-cli"), false).expect_err("must fail");
        assert!(matches!(err, SdkError::InvalidRequest(_)));
    }

    #[test]
    fn cli_binary_validation_allows_path_lookup_name_with_opt_in() {
        assert!(validate_cli_binary_path(Path::new("provenact-cli"), true).is_ok());
    }

    #[test]
    fn cli_binary_validation_rejects_relative_paths_with_opt_in() {
        let err = validate_cli_binary_path(Path::new("./bin/provenact-cli"), true)
            .expect_err("must fail");
        assert!(matches!(err, SdkError::InvalidRequest(_)));
    }
}
