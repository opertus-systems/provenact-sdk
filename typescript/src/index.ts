import { readFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { isAbsolute } from "node:path";

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
      if (!isAbsolute(this.bin) && !allowPathCli) {
        reject(
          new SdkError(
            "INVALID_REQUEST",
            "CliRunner binary must be an absolute path; set PROVENACT_ALLOW_PATH_CLI=1 to opt into PATH lookup"
          )
        );
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
    const keysDigest = validateRequest(req);
    const args = ["verify", "--bundle", req.bundle, "--keys", req.keys];
    args.push("--keys-digest", keysDigest);
    appendCommonFlags(args, req);

    const stdout = await this.runner.run(args);
    return { stdout };
  }

  async executeVerified(req: ExecuteRequest): Promise<ExecuteOutput> {
    const keysDigest = validateRequest(req);
    const args = [
      "run",
      "--bundle",
      req.bundle,
      "--keys",
      req.keys,
      "--keys-digest",
      keysDigest,
      "--policy",
      req.policy,
      "--input",
      req.input,
      "--receipt",
      req.receipt,
    ];
    appendCommonFlags(args, req);

    const stdout = await this.runner.run(args);
    return { stdout, receiptPath: req.receipt };
  }

  async parseReceipt(path: string): Promise<Receipt> {
    let data: string;
    try {
      data = await readFile(path, "utf8");
    } catch (err) {
      throw new SdkError("IO_ERROR", (err as Error).message);
    }

    try {
      return { raw: JSON.parse(data) };
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

function validateRequest(req: CommonRequest): string {
  const keysDigest = normalizeOptional(req.keysDigest);
  if (!keysDigest) {
    throw new SdkError("INVALID_REQUEST", "keysDigest is required and must not be blank");
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
