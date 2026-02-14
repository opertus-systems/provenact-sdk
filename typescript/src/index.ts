import { readFile, stat } from "node:fs/promises";
import { spawn } from "node:child_process";
import { isAbsolute } from "node:path";

const SHA256_HEX_LEN = 64;
const MAX_RECEIPT_BYTES = 1_048_576;

export interface VerifyRequest {
  bundle: string;
  keys: string;
  keysDigest: string;
  requireCosign?: boolean;
  ociRef?: string;
  cosignKey?: string;
  cosignCertIdentity?: string;
  cosignCertOidcIssuer?: string;
  allowExperimental?: boolean;
}

export interface ExecuteRequest {
  bundle: string;
  keys: string;
  keysDigest: string;
  policy: string;
  input: string;
  receipt: string;
  requireCosign?: boolean;
  ociRef?: string;
  cosignKey?: string;
  cosignCertIdentity?: string;
  cosignCertOidcIssuer?: string;
  allowExperimental?: boolean;
}

export interface VerifyOutput {
  stdout: string;
}

export interface ExecuteOutput {
  stdout: string;
  receiptPath: string;
}

export interface Receipt {
  raw: unknown;
}

type CommonRequest = {
  keysDigest?: string;
  requireCosign?: boolean;
  ociRef?: string;
  cosignKey?: string;
  cosignCertIdentity?: string;
  cosignCertOidcIssuer?: string;
  allowExperimental?: boolean;
};

export type ErrorCode =
  | "INVALID_REQUEST"
  | "COMMAND_FAILED"
  | "IO_ERROR"
  | "JSON_ERROR";

export class SdkError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = "SdkError";
    this.code = code;
  }
}

export interface CommandRunner {
  run(args: string[]): Promise<string>;
}

export class CliRunner implements CommandRunner {
  readonly bin: string;

  constructor(bin = "provenact-cli") {
    this.bin = bin;
  }

  run(args: string[]): Promise<string> {
    return new Promise((resolve, reject) => {
      const allowPathCli = /^(1|true)$/i.test(process.env.PROVENACT_ALLOW_PATH_CLI ?? "");
      const binaryError = validateCliBinary(this.bin, allowPathCli);
      if (binaryError) {
        reject(binaryError);
        return;
      }
      const child = spawn(this.bin, args, { stdio: ["ignore", "pipe", "pipe"] });
      const stdoutChunks: Buffer[] = [];
      const stderrChunks: Buffer[] = [];

      child.stdout.on("data", (chunk) => stdoutChunks.push(Buffer.from(chunk)));
      child.stderr.on("data", (chunk) => stderrChunks.push(Buffer.from(chunk)));
      child.on("error", (err) => reject(new SdkError("IO_ERROR", err.message)));
      child.on("close", (code) => {
        if (code === 0) {
          resolve(Buffer.concat(stdoutChunks).toString("utf8"));
          return;
        }
        reject(
          new SdkError(
            "COMMAND_FAILED",
            Buffer.concat(stderrChunks).toString("utf8").trim() ||
              `${this.bin} exited with status ${code}`
          )
        );
      });
    });
  }
}

export class ProvenactSdk {
  private readonly runner: CommandRunner;

  constructor(runner: CommandRunner = new CliRunner()) {
    this.runner = runner;
  }

  async verifyBundle(req: VerifyRequest): Promise<VerifyOutput> {
    const bundle = validateRequiredPath(req.bundle, "bundle");
    const keys = validateRequiredPath(req.keys, "keys");
    const keysDigest = validateRequest(req);
    const args = ["verify", "--bundle", bundle, "--keys", keys];
    args.push("--keys-digest", keysDigest);
    appendCommonFlags(args, req);

    const stdout = await this.runner.run(args);
    return { stdout };
  }

  async executeVerified(req: ExecuteRequest): Promise<ExecuteOutput> {
    const bundle = validateRequiredPath(req.bundle, "bundle");
    const keys = validateRequiredPath(req.keys, "keys");
    const policy = validateRequiredPath(req.policy, "policy");
    const input = validateRequiredPath(req.input, "input");
    const receipt = validateRequiredPath(req.receipt, "receipt");
    const keysDigest = validateRequest(req);
    const args = [
      "run",
      "--bundle",
      bundle,
      "--keys",
      keys,
      "--keys-digest",
      keysDigest,
      "--policy",
      policy,
      "--input",
      input,
      "--receipt",
      receipt,
    ];
    appendCommonFlags(args, req);

    const stdout = await this.runner.run(args);
    return { stdout, receiptPath: receipt };
  }

  async parseReceipt(path: string): Promise<Receipt> {
    const receiptPath = validateRequiredPath(path, "receipt");
    let metadata: Awaited<ReturnType<typeof stat>>;
    try {
      metadata = await stat(receiptPath);
    } catch (err) {
      throw new SdkError("IO_ERROR", (err as Error).message);
    }
    if (!metadata.isFile()) {
      throw new SdkError("INVALID_REQUEST", "receipt path must point to a regular file");
    }
    if (metadata.size > MAX_RECEIPT_BYTES) {
      throw new SdkError(
        "INVALID_REQUEST",
        `receipt file exceeds maximum size of ${MAX_RECEIPT_BYTES} bytes`
      );
    }

    let data: Buffer;
    try {
      data = await readFile(receiptPath);
    } catch (err) {
      throw new SdkError("IO_ERROR", (err as Error).message);
    }
    if (data.byteLength > MAX_RECEIPT_BYTES) {
      throw new SdkError(
        "INVALID_REQUEST",
        `receipt file exceeds maximum size of ${MAX_RECEIPT_BYTES} bytes`
      );
    }

    try {
      return { raw: JSON.parse(data.toString("utf8")) };
    } catch (err) {
      throw new SdkError("JSON_ERROR", (err as Error).message);
    }
  }
}

export const experimental = {
  async validateManifestV1(runner: CommandRunner, manifest: string): Promise<string> {
    return runner.run(["experimental-validate-manifest-v1", "--manifest", manifest]);
  },

  async validateReceiptV1(runner: CommandRunner, receipt: string): Promise<string> {
    return runner.run(["experimental-validate-receipt-v1", "--receipt", receipt]);
  },
};

function normalizeOptional(value: string | undefined): string | undefined {
  const normalized = value?.trim();
  return normalized ? normalized : undefined;
}

function validateRequiredPath(path: string, field: string): string {
  if (typeof path !== "string" || path.trim().length === 0) {
    throw new SdkError("INVALID_REQUEST", `${field} is required and must not be blank`);
  }
  if (path !== path.trim() || /[\u0000-\u001f\u007f]/.test(path)) {
    throw new SdkError(
      "INVALID_REQUEST",
      `${field} must not include leading/trailing whitespace or control characters`
    );
  }
  return path;
}

function validateRequest(req: CommonRequest): string {
  const keysDigest = normalizeOptional(req.keysDigest);
  if (!keysDigest) {
    throw new SdkError("INVALID_REQUEST", "keysDigest is required and must not be blank");
  }
  if (!isValidSha256PrefixedHex(keysDigest)) {
    throw new SdkError("INVALID_REQUEST", "keysDigest must match sha256:<64 lowercase hex>");
  }
  if (req.requireCosign && !normalizeOptional(req.ociRef)) {
    throw new SdkError("INVALID_REQUEST", "ociRef is required when requireCosign is true");
  }
  if (req.requireCosign && !normalizeOptional(req.cosignKey)) {
    throw new SdkError("INVALID_REQUEST", "cosignKey is required when requireCosign is true");
  }
  if (req.requireCosign && !normalizeOptional(req.cosignCertIdentity)) {
    throw new SdkError("INVALID_REQUEST", "cosignCertIdentity is required when requireCosign is true");
  }
  if (req.requireCosign && !normalizeOptional(req.cosignCertOidcIssuer)) {
    throw new SdkError("INVALID_REQUEST", "cosignCertOidcIssuer is required when requireCosign is true");
  }
  return keysDigest;
}

function appendCommonFlags(args: string[], req: CommonRequest): void {
  if (req.requireCosign) {
    args.push("--require-cosign");
  }
  const ociRef = normalizeOptional(req.ociRef);
  if (ociRef) {
    args.push("--oci-ref", ociRef);
  }
  const cosignKey = normalizeOptional(req.cosignKey);
  if (cosignKey) {
    args.push("--cosign-key", cosignKey);
  }
  const cosignCertIdentity = normalizeOptional(req.cosignCertIdentity);
  if (cosignCertIdentity) {
    args.push("--cosign-cert-identity", cosignCertIdentity);
  }
  const cosignCertOidcIssuer = normalizeOptional(req.cosignCertOidcIssuer);
  if (cosignCertOidcIssuer) {
    args.push("--cosign-cert-oidc-issuer", cosignCertOidcIssuer);
  }
  if (req.allowExperimental) {
    args.push("--allow-experimental");
  }
}

function isValidSha256PrefixedHex(value: string): boolean {
  if (!value.startsWith("sha256:")) {
    return false;
  }
  const digest = value.slice("sha256:".length);
  if (digest.length !== SHA256_HEX_LEN) {
    return false;
  }
  return /^[0-9a-f]+$/.test(digest);
}

function validateCliBinary(bin: string, allowPathCli: boolean): SdkError | null {
  if (isAbsolute(bin)) {
    return null;
  }
  if (!allowPathCli) {
    return new SdkError(
      "INVALID_REQUEST",
      "CliRunner binary must be an absolute path; set PROVENACT_ALLOW_PATH_CLI=1 to opt into PATH lookup"
    );
  }
  if (!isPathLookupName(bin)) {
    return new SdkError(
      "INVALID_REQUEST",
      "CliRunner binary must be a simple command name when PROVENACT_ALLOW_PATH_CLI=1"
    );
  }
  return null;
}

function isPathLookupName(bin: string): boolean {
  const trimmed = bin.trim();
  if (!trimmed || trimmed !== bin) {
    return false;
  }
  return !trimmed.includes("/") && !trimmed.includes("\\");
}
